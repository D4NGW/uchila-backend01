'use strict';

const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const axios = require('axios');
const crypto = require('crypto');
const corsMiddleware = require('cors');
const mongoose = require('mongoose');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const compression = require('compression');
require('dotenv').config();

// --- INSTÂNCIA DE IDENTIFICAÇÃO DO SERVIDOR ---
const SERVER_INSTANCE_ID = crypto.randomUUID();

// --- FLAG DE CONTROLO CONTRA LOOPS NO SHUTDOWN ---
let isShuttingDown = false;

// --- TRATAMENTO GLOBAL DE FALHAS ASSÍNCRONAS ---
process.on('unhandledRejection', (err) => {
    console.error('[CRITICAL] Unhandled Rejection detetada:', err.stack || err);
    if (isShuttingDown) {
        console.error('[CRITICAL] Erro fatal durante o shutdown. Forçando terminação imediata.');
        process.exit(1);
    }
    executarGracefulShutdown('UNHANDLED_REJECTION');
});

process.on('uncaughtException', (err) => {
    console.error('[CRITICAL] Uncaught Exception lançada:', err.stack || err.message);
    if (isShuttingDown) {
        console.error('[CRITICAL] Erro fatal durante o shutdown. Forçando terminação imediata.');
        process.exit(1);
    }
    executarGracefulShutdown('UNCAUGHT_EXCEPTION');
});

const app = express();

// --- MIDDLEWARES DE PRODUÇÃO ---
app.use(helmet({ contentSecurityPolicy: false }));
app.use(compression());
app.use(express.json({ limit: '10kb' }));

const apiLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 30,
    message: { error: 'Excesso de requisições. Tente novamente mais tarde.' },
    standardHeaders: true,
    legacyHeaders: false,
});
app.use('/api/', apiLimiter);

// --- CONFIGURAÇÕES GLOBAIS DE ARQUITETURA ---
const MAX_HISTORY = 45; 
const MAX_MONGO_QUEUE_SIZE = 500;
const GLOBAL_MONGO_QUEUE_LIMIT = 5000;
const CIRCUIT_BREAKER_WINDOW_MS = 900000;
const LEASE_TIME_LOCK_MS = 20000;
const LEASE_UPDATE_INTERVAL_MS = 8000;
const MAX_WS_PAYLOAD_BYTES = 2000;
const MAX_ACTIVE_CLIENTS = 200; 
const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const VERCEL_PREVIEW_REGEX = /^https:\/\/[a-z0-9-]+-uchilabotv9\.vercel\.app$/i;
const ALLOWED_ORIGINS = ['http://localhost:5500', 'http://127.0.0.1:5500', 'https://uchilabotv9.vercel.app'];

let totalGlobalMongoUpdatesInRam = 0;

if (!process.env.ENCRYPTION_KEY || !process.env.SESSION_SECRET || !process.env.DERIV_APP_ID || !process.env.REDIRECT_URI) {
    console.error('CRITICAL: Variáveis de ambiente vitais ausentes no .env!');
    process.exit(1);
}

if (!/^[0-9a-fA-F]{64}$/.test(process.env.ENCRYPTION_KEY)) {
    console.error('CRITICAL: ENCRYPTION_KEY precisa ser uma string hexadecimal válida de 64 caracteres!');
    process.exit(1);
}

const ENCRYPTION_KEY = Buffer.from(process.env.ENCRYPTION_KEY, 'hex');

// --- MÓDULO CRIPTOGRÁFICO ---
function encrypt(text) {
    if (!text) return null;
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', ENCRYPTION_KEY, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return `${iv.toString('hex')}:${encrypted}:${cipher.getAuthTag().toString('hex')}`;
}

// --- LIMPEZA DE RECURSOS AUXILIAR ---
function limparRecursosSessao(sessionId) {
    const runtime = sessionRuntimes.get(sessionId);
    if (runtime && runtime.watchdogInterval) {
        clearInterval(runtime.watchdogInterval);
    }
}

function decrypt(text) {
    if (typeof text !== 'string' || text.split(':').length !== 3) return null;
    try {
        const [ivHex, encrypted, authTagHex] = text.split(':');
        const decipher = crypto.createDecipheriv('aes-256-gcm', ENCRYPTION_KEY, Buffer.from(ivHex, 'hex'));
        decipher.setAuthTag(Buffer.from(authTagHex, 'hex'));
        return decipher.update(encrypted, 'hex', 'utf8') + decipher.final('utf8');
    } catch (e) { 
        console.error('[CRYPTOGRAPHY] Falha ao descriptografar token:', e.message);
        return null; 
    }
}

const STATES = {
    IDLE: 'IDLE',
    PROPOSAL: 'PROPOSAL',
    BUYING: 'BUYING',
    AWAITING_RESULT: 'AWAITING_RESULT',
    STOPPED: 'STOPPED'
};

// --- ENGINE MEMORY CACHE LAYER ---
const activeDerivSockets = new Map();
const activeClientSockets = new Map();
const sessionRuntimes = new Map();
const sessionSalts = new Map();
const sessionSaltLastAccess = new Map();
const clientOrphanTimers = new Map();

// --- BASE DE DADOS (MONGOOSE) ---
let isMongoConfigured = false;
let SessionModel = null;
const mongoWriteQueues = new Map();

if (process.env.MONGO_URI) {
    isMongoConfigured = true;

    mongoose.connection.on('disconnected', () => {  
        console.error('[MongoDB] Conexão perdida. Sincronização retida em RAM.');  
    });  

    mongoose.connection.on('reconnected', () => {  
        console.log('[MongoDB] Conexão reestabelecida. Processando filas...');  
        for (const sid of mongoWriteQueues.keys()) {  
            processarProximaEscritaMongo(sid);  
        }  
    });  

    mongoose.connection.on('error', (err) => {  
        console.error('[MongoDB] Erro na instância:', err.message);  
    });  

    mongoose.connect(process.env.MONGO_URI, {  
        serverSelectionTimeoutMS: 10000,  
        socketTimeoutMS: 45000,  
        maxPoolSize: 20  
    })  
    .then(() => {  
        console.log('[MongoDB] Conectado com sucesso.');  
        executarStartupRecovery();  
    })  
    .catch(err => console.error('[MongoDB Erro Inicial]:', err.message));  

    const SessionSchema = new mongoose.Schema({  
        _id: String,  
        sessionSalt: String,  
        accessTokenEnc: String,  
        refreshTokenEnc: String,  
        expiresAt: Number,  
        botRunning: { type: Boolean, default: false },  
        lockTimestamp: { type: Number, default: 0 },   
        serverId: { type: String, default: null },  
        tradingState: { type: String, default: STATES.IDLE },  
        metrics: {  
            totalTrades: { type: Number, default: 0 },  
            wins: { type: Number, default: 0 },  
            losses: { type: Number, default: 0 },  
            consecLosses: { type: Number, default: 0 }  
        },  
        config: {  
            type: Object,  
            default: { stake: 1.0 },  
            validate: {  
                validator: function(v) {  
                    if (!v || typeof v !== 'object') return false;  
                    const s = parseFloat(v.stake);  
                    return Number.isFinite(s) && s >= 0.35 && s <= 1000.0;  
                },  
                message: 'Parâmetros inválidos ou stake fora dos limites.'  
            }  
        },  
        updatedAt: { type: Date, default: Date.now, expires: 2592000 }   
    });  

    SessionSchema.index({ lockTimestamp: 1 });  
    SessionSchema.index({ botRunning: 1 });  
    SessionSchema.index({ serverId: 1 });  

    SessionModel = mongoose.models.Session || mongoose.model('Session', SessionSchema);
}

// --- FILA ASSÍNCRONA COM BACKPRESSURE ---
function enfileirarEscritaMongo(sessionId, updatePayload, critical = false) {
    if (!isMongoConfigured || !SessionModel) return;

    if (totalGlobalMongoUpdatesInRam >= GLOBAL_MONGO_QUEUE_LIMIT && !critical) {  
        return;   
    }  

    if (!mongoWriteQueues.has(sessionId)) {  
        mongoWriteQueues.set(sessionId, { queue: [], processing: false });  
    }  
  
    const context = mongoWriteQueues.get(sessionId);  
  
    if (context.queue.length >= MAX_MONGO_QUEUE_SIZE && !critical) {  
        if (!context.queue[0]?.critical) {  
            context.queue.shift();  
            totalGlobalMongoUpdatesInRam--;  
        }  
    }  

    // Correção Estrutural de Sintaxe (Removido '=' inválido de atribuição dentro de objeto literal)
    if (updatePayload.$set) {  
        updatePayload.$set.updatedAt = new Date();  
    } else if (!updatePayload.$inc) {  
        updatePayload.$set = { updatedAt: new Date() };  
    } else {
        updatePayload.$set = { updatedAt: new Date() };
    }

    context.queue.push({ payload: updatePayload, critical, timestamp: Date.now() });  
    totalGlobalMongoUpdatesInRam++;  
  
    if (!context.processing && mongoose.connection.readyState === 1) {  
        processarProximaEscritaMongo(sessionId);  
    }
}

async function processarProximaEscritaMongo(sessionId) {
    const context = mongoWriteQueues.get(sessionId);
    if (!context || context.processing) return;

    if (mongoose.connection.readyState !== 1 || !SessionModel) return;  
    if (context.queue.length === 0) return;  

    if (Date.now() - context.queue[0].timestamp > 600000 && !context.queue[0].critical) {  
        context.queue.shift();  
        totalGlobalMongoUpdatesInRam--;  
        if (context.queue.length > 0) {  
            setImmediate(() => processarProximaEscritaMongo(sessionId));  
        }  
        return;  
    }  

    context.processing = true;  
    const currentContainer = context.queue[0];  
    const currentUpdate = currentContainer.payload;  

    try {  
        await SessionModel.findByIdAndUpdate(  
            sessionId,   
            currentUpdate,   
            { new: true, upsert: true, writeConcern: { w: 1, wtimeout: 4000 } }  
        ).maxTimeMS(4000);  
      
        context.queue.shift();   
        totalGlobalMongoUpdatesInRam--;  
        context.processing = false;  
    } catch (err) {  
        context.processing = false;  
        console.error(`[DATABASE QUEUE] Erro ao processar escrita para ${sessionId}:`, err.message);
        if (mongoose.connection.readyState !== 1) return;  
        context.queue.shift();  
        totalGlobalMongoUpdatesInRam--;  
    }  
  
    if (context.queue.length > 0) {  
        setImmediate(() => processarProximaEscritaMongo(sessionId));  
    }
}

// --- DECLARAÇÃO DE FUNÇÃO ANTECIPADA PARA STARTUP RECOVERY ---
function inicializarBotDeriv(sessionId) {
    if (!sessionRuntimes.has(sessionId)) return;
    const runtime = sessionRuntimes.get(sessionId);
    
    const derivWs = new WebSocket(DERIV_WS_URL);
    activeDerivSockets.set(sessionId, derivWs);

    derivWs.on('open', () => {
        derivWs.send(JSON.stringify({ authorize: runtime.token }));
    });

    derivWs.on('message', (response) => {
        const res = JSON.parse(response);
        runtime.lastDerivPong = Date.now();

        if (res.msg_type === 'authorize' && !res.error) {
            derivWs.send(JSON.stringify({ ticks: 'R_100', subscribe: 1 }));
            derivWs.send(JSON.stringify({ proposal_open_contract: 1, subscribe: 1 }));
        }

        if (res.msg_type === 'tick' && res.tick) {
            const quote = res.tick.quote;
            const ultimoDigito = parseInt(quote.toString().slice(-1), 10);
            runtime.lastTickTime = Date.now();
            
            runtime.history.push(ultimoDigito);
            if (runtime.history.length > MAX_HISTORY) {
                runtime.history = runtime.history.slice(-MAX_HISTORY);
            }

            // Exemplo de verificação estruturada antes de requisitar PROPOSAL
            if (runtime.tradingState === STATES.IDLE && !runtime.buyInProgress) {
                runtime.tradeVersion++;
                runtime.tradingState = STATES.PROPOSAL;
                runtime.stateTimestamp = Date.now();

                derivWs.send(JSON.stringify({
                    proposal: 1,
                    amount: runtime.config.stake,
                    basis: 'stake',
                    currency: 'USD',
                    duration: 1,
                    duration_unit: 't',
                    criterion: 'MATCHES',
                    barrier: '5',
                    symbol: 'R_100',
                    passthrough: { versionCheck: runtime.tradeVersion }
                }));
            }
        }

        if (res.msg_type === 'proposal' && !res.error) {
            const proposalId = res.proposal.id;
            const passthroughVersion = res.echo_req.passthrough?.versionCheck;

            // Correção de Vazamento de Memória (Evita acúmulo descontrolado sob alto volume de ticks)
            if (runtime.proposalsSeenMap.size > 500) {
                runtime.proposalsSeenMap.clear();
            }

            if (runtime.proposalsSeenMap.has(proposalId)) return;
            if (runtime.buyInProgress || passthroughVersion !== runtime.tradeVersion) return;

            runtime.proposalsSeenMap.set(proposalId, Date.now());
            runtime.buyInProgress = true;
            runtime.tradingState = STATES.BUYING;
            runtime.stateTimestamp = Date.now();

            derivWs.send(JSON.stringify({ buy: proposalId, price: runtime.config.stake }));
        }

        if (res.msg_type === 'proposal_open_contract' && res.proposal_open_contract) {
            const contract = res.proposal_open_contract;
            
            // Correção Avançada: Evita contratos órfãos ou travados em 'AWAITING_RESULT'
            if (contract && (contract.is_expired || contract.is_sold)) {
                runtime.buyInProgress = false;
                runtime.tradingState = STATES.IDLE;
                runtime.stateTimestamp = Date.now();
                
                const win = contract.status === 'won';
                const profit = contract.profit;

                const incPayload = {
                    'metrics.totalTrades': 1,
                    [win ? 'metrics.wins' : 'metrics.losses']: 1
                };

                enfileirarEscritaMongo(sessionId, { 
                    $inc: incPayload, 
                    $set: { tradingState: STATES.IDLE, botRunning: true } 
                }, true);

                const clientWs = activeClientSockets.get(sessionId);
                if (clientWs && clientWs.readyState === WebSocket.OPEN) {
                    clientWs.send(JSON.stringify({ type: 'TRADE_RESULT', win, profit }));
                }
            }
        }

        if (res.error) {
            runtime.failuresTimeline.push(Date.now());
            runtime.buyInProgress = false;
            runtime.tradingState = STATES.IDLE;

            // Correção Dinâmica de Segurança: Circuit Breaker mais reativo (reduzido para 15)
            const tempoJanela = Date.now() - CIRCUIT_BREAKER_WINDOW_MS;
            runtime.failuresTimeline = runtime.failuresTimeline.filter(t => t > tempoJanela);

            if (runtime.failuresTimeline.length >= 15) {
                console.error(`[CIRCUIT BREAKER] Ativado para a sessão: ${sessionId}`);
                desativarSessaoLocal(sessionId);
            }
        }
    });

    derivWs.on('close', () => {
        if (sessionRuntimes.has(sessionId) && runtime.tradingState !== STATES.STOPPED) {
            // Tentativa simples de reconexão automática controlada
            setTimeout(() => {
                if (sessionRuntimes.has(sessionId) && runtime.tradingState !== STATES.STOPPED) {
                    inicializarBotDeriv(sessionId);
                }
            }, 5000);
        }
    });

    derivWs.on('error', (err) => {
        console.error(`[Deriv Socket Erro] na sessão ${sessionId.slice(0, 8)}:`, err.message);
    });
}

// --- ROTINA DE STARTUP RECOVERY ---
async function executarStartupRecovery() {
    if (!isMongoConfigured || !SessionModel) return;
    try {
        console.log('[Startup Recovery] Verificando integridade de sessões órfãs...');
        const sessoesOrfas = await SessionModel.find({
            botRunning: true,
            $or: [
                { serverId: SERVER_INSTANCE_ID },
                { lockTimestamp: { $lt: Date.now() - LEASE_TIME_LOCK_MS } }
            ]
        }).maxTimeMS(10000);

        console.log(`[Startup Recovery] Encontradas ${sessoesOrfas.length} sessões prontas para restauração.`);  
      
        for (const doc of sessoesOrfas) {  
            const sessionId = doc._id;  
            const sessionData = doc.toObject();  
            const tokenDec = decrypt(sessionData.accessTokenEnc);  
            const refreshDec = decrypt(sessionData.refreshTokenEnc);  

            if (!tokenDec && !refreshDec) continue;  

            const baseMetrics = sessionData.metrics || { totalTrades: 0, wins: 0, losses: 0, consecLosses: 0 };  

            sessionRuntimes.set(sessionId, {  
                token: tokenDec,  
                refreshToken: refreshDec,  
                expiresAt: sessionData.expiresAt || 0,  
                tradingState: STATES.IDLE,   
                buyInProgress: false,  
                startingBot: false,  
                generationId: 1,
                lastAccessed: Date.now(),  
                lastLeaseUpdate: Date.now(),  
                reconnectAttempts: 0,  
                failuresTimeline: [],   
                cooldownAtivo: 0,  
                tradeVersion: 0,  
                lastTickTime: Date.now(),  
                lastDerivPong: Date.now(),  
                balance: 0,  
                balanceSynced: false,   
                history: [],  
                proposalsSeenMap: new Map(),
                metrics: {   
                    totalTrades: baseMetrics.totalTrades,   
                    wins: baseMetrics.wins,   
                    losses: baseMetrics.losses,   
                    consecLosses: baseMetrics.consecLosses  
                },  
                config: sessionData.config || { stake: 1.0 },  
                refreshPromise: null,  
                rateLimit: { windowStart: Date.now(), count: 0 },  
                tentativasRefresh: 0  
            });  

            await SessionModel.findByIdAndUpdate(sessionId, {  
                $set: { serverId: SERVER_INSTANCE_ID, lockTimestamp: Date.now() }  
            });  

            inicializarBotDeriv(sessionId);  
        }  
    } catch (err) {  
        console.error('[Startup Recovery Erro]:', err.message);  
    }
}

function extrairErroAxios(err) {
    if (err.code === 'ECONNRESET') return 'Conexão resetada de forma abrupta (ECONNRESET).';
    if (err.code === 'ETIMEDOUT') return 'Timeout de rede esgotado (ETIMEDOUT).';
    if (err.code === 'EPIPE') return 'Broken pipe de socket (EPIPE).';
    return err.message;
}

app.use(corsMiddleware({
    origin: (origin, callback) => {
        const isVercelValidProject = typeof origin === 'string' && VERCEL_PREVIEW_REGEX.test(origin);
        if (!origin || ALLOWED_ORIGINS.includes(origin) || isVercelValidProject) {
            callback(null, true);
        } else {
            callback(new Error('Bloqueado pelas diretrizes estritas de segurança CORS.'));
        }
    },
    credentials: true
}));

const DERIV_TOKEN_URL = 'https://oauth.deriv.com/oauth2/token';
const DERIV_WS_URL = `wss://ws.derivws.com/websockets/v3?app_id=${process.env.DERIV_APP_ID}`;

function gerarAssinaturaSessao(sessionId, salt, timestamp) {
    return crypto.createHmac('sha256', process.env.SESSION_SECRET).update(`${sessionId}:${salt}:${timestamp}`).digest('hex');
}

async function garantirTokenValido(sessionId) {
    if (!sessionRuntimes.has(sessionId)) return null;
    const runtime = sessionRuntimes.get(sessionId);

    runtime.lastAccessed = Date.now();   

    if (runtime.expiresAt && Date.now() < (runtime.expiresAt - 300000)) {  
        return runtime.token;  
    }  

    if (!runtime.refreshToken) return runtime.token;   
    if (runtime.refreshPromise) return runtime.refreshPromise;  

    if (runtime.tentativasRefresh === undefined) runtime.tentativasRefresh = 0;  

    runtime.refreshPromise = (async () => {  
        try {  
            if (!sessionRuntimes.has(sessionId)) return null;  

            const response = await axios.post(DERIV_TOKEN_URL, {  
                grant_type: 'refresh_token',  
                refresh_token: runtime.refreshToken,  
                client_id: process.env.DERIV_APP_ID,  
                redirect_uri: process.env.REDIRECT_URI  
            }, { timeout: 15000 });  

            if (!sessionRuntimes.has(sessionId)) return null;  

            const novoExpiresAt = Date.now() + (response.data.expires_in * 1000);  
            const novoRefreshToken = response.data.refresh_token ?? runtime.refreshToken;  
            const novoAccessToken = response.data.access_token;  

            enfileirarEscritaMongo(sessionId, {  
                $set: {  
                    accessTokenEnc: encrypt(novoAccessToken),  
                    refreshTokenEnc: encrypt(novoRefreshToken),  
                    expiresAt: novoExpiresAt  
                }  
            }, true);  

            runtime.token = novoAccessToken;  
            runtime.refreshToken = novoRefreshToken;  
            runtime.expiresAt = novoExpiresAt;  
            runtime.tentativasRefresh = 0;  

            return novoAccessToken;  
        } catch (err) {  
            runtime.tentativasRefresh++;  
            console.error(`[OAuth Refresh Falha] em ${sessionId.slice(0, 8)}:`, extrairErroAxios(err));  
              
            if (runtime.tentativasRefresh >= 2) {  
                runtime.tentativasRefresh = 0;  
                desativarSessaoLocal(sessionId);  
            }  
            return null;   
        } finally {  
            if (sessionRuntimes.has(sessionId)) {  
                sessionRuntimes.get(sessionId).refreshPromise = null;  
            }  
        }  
    })();  

    return runtime.refreshPromise;
}

async function buscarSessao(sessionId) {
    const runtime = sessionRuntimes.get(sessionId);
    if (runtime) {
        const rawMetrics = runtime.metrics || { totalTrades: 0, wins: 0, losses: 0, consecLosses: 0 };
        const calculatedWinRate = rawMetrics.totalTrades > 0 ? Math.round((rawMetrics.wins / rawMetrics.totalTrades) * 100) : 0;

        return {  
            accessToken: runtime.token,  
            refreshToken: runtime.refreshToken,  
            expiresAt: runtime.expiresAt,  
            botRunning: runtime.tradingState !== STATES.STOPPED,  
            tradingState: runtime.tradingState,  
            metrics: { ...rawMetrics, winRate: calculatedWinRate },  
            config: runtime.config || { stake: 1.0 }  
        };  
    }  

    if (!isMongoConfigured || mongoose.connection.readyState !== 1 || !SessionModel) return null;  

    try {
        const doc = await SessionModel.findById(sessionId).maxTimeMS(5000);  
        if (!doc) return null;  
        const sessionData = doc.toObject();  
        sessionData.accessToken = decrypt(sessionData.accessTokenEnc);  
        sessionData.refreshToken = decrypt(sessionData.refreshTokenEnc);  
      
        if (sessionData.metrics) {  
            const t = sessionData.metrics.totalTrades || 0;  
            const w = sessionData.metrics.wins || 0;  
            sessionData.metrics.winRate = t > 0 ? Math.round((w / t) * 100) : 0;  
        }  
        return sessionData;  
    } catch(e) {  
        console.error(`[DATABASE] Erro ao buscar sessão ${sessionId}:`, e.message);
        return null;  
    }
}

// --- TELEMETRIA / HEALTH ---
app.get('/health', async (req, res) => {
    const authHeader = req.headers['x-monitoring-key'];
    if (process.env.MONITORING_KEY && authHeader !== process.env.MONITORING_KEY) {
        return res.status(401).json({ error: 'Não autorizado.' });
    }

    let derivStatus = 'OK';  
    if (sessionRuntimes.size > 0) {  
        const socketsEmPai = Array.from(activeDerivSockets.values());  
        const abertos = socketsEmPai.filter(s => s.readyState === WebSocket.OPEN).length;  
        derivStatus = `${abertos}/${socketsEmPai.length} OPEN`;  
    }  

    const mem = process.memoryUsage();

    res.json({  
        status: 'UP',  
        timestamp: Date.now(),  
        nodeVersion: process.version,  
        memoryUsageMB: {
            rss: Math.round(mem.rss / 1024 / 1024),
            heapUsed: Math.round(mem.heapUsed / 1024 / 1024)
        },   
        database: isMongoConfigured ? (mongoose.connection.readyState === 1 ? 'CONNECTED' : 'DISCONNECTED') : 'NOT_CONFIGURED',  
        activeEngines: sessionRuntimes.size,  
        derivSocketsState: derivStatus,  
        globalMongoRamUpdates: totalGlobalMongoUpdatesInRam  
    });
});

app.post('/api/auth/callback', async (req, res) => {
    const { code, code_verifier } = req.body;

    if (typeof code !== 'string' || typeof code_verifier !== 'string') {  
        return res.status(400).json({ error: 'Parâmetros inválidos.' });  
    }  

    try {  
        const response = await axios.post(DERIV_TOKEN_URL, {  
            grant_type: 'authorization_code', code, code_verifier,  
            client_id: process.env.DERIV_APP_ID, redirect_uri: process.env.REDIRECT_URI  
        }, { timeout: 15000 });  

        if (!response.data || !response.data.refresh_token) {  
            return res.status(422).json({ error: 'A corretora não forneceu um token de renovação válido.' });  
        }  

        const sessionId = crypto.randomUUID();  
        const sessionSalt = crypto.randomBytes(16).toString('hex');  
        const expiresAtValue = Date.now() + (response.data.expires_in * 1000);  

        sessionSalts.set(sessionId, sessionSalt);  
        sessionSaltLastAccess.set(sessionId, Date.now());  

        sessionRuntimes.set(sessionId, {   
            token: response.data.access_token,   
            refreshToken: response.data.refresh_token,  
            expiresAt: expiresAtValue,  
            tradingState: STATES.IDLE,  
            buyInProgress: false,  
            startingBot: false,   
            generationId: 1,
            lastAccessed: Date.now(),  
            lastLeaseUpdate: Date.now(),   
            reconnectAttempts: 0,  
            failuresTimeline: [],   
            cooldownAtivo: 0,  
            tradeVersion: 0,  
            lastTickTime: Date.now(),  
            lastDerivPong: Date.now(),   
            balance: 0,  
            balanceSynced: false,   
            history: [],  
            proposalsSeenMap: new Map(),   
            metrics: { totalTrades: 0, wins: 0, losses: 0, consecLosses: 0 },  
            config: { stake: 1.0 },  
            refreshPromise: null,  
            rateLimit: { windowStart: Date.now(), count: 0 },  
            tentativasRefresh: 0  
        });  

        if (isMongoConfigured && mongoose.connection.readyState === 1 && SessionModel) {  
            await new SessionModel({  
                _id: sessionId,   
                sessionSalt,  
                accessTokenEnc: encrypt(response.data.access_token),  
                refreshTokenEnc: encrypt(response.data.refresh_token),  
                expiresAt: expiresAtValue,  
                botRunning: false,  
                lockTimestamp: 0,  
                serverId: SERVER_INSTANCE_ID,  
                tradingState: STATES.IDLE,  
                metrics: { totalTrades: 0, wins: 0, losses: 0, consecLosses: 0 },  
                config: { stake: 1.0 }  
            }).save({ writeConcern: { w: 1, wtimeout: 5000 } });  
        }  

        const timestampSincrono = Date.now();  
        res.json({   
            success: true,   
            sessionId,   
            salt: sessionSalt,   
            timestamp: timestampSincrono,  
            signature: gerarAssinaturaSessao(sessionId, sessionSalt, timestampSincrono)  
        });  
    } catch (e) {   
        res.status(500).json({ error: 'Erro no handshake de credenciais: ' + extrairErroAxios(e) });   
    }
});

const server = http.createServer(app);

const wss = new WebSocket.Server({
    server,
    path: '/api/ws',
    maxPayload: MAX_WS_PAYLOAD_BYTES
});

// --- TIMERS CENTRALIZADOS ---
let isWssServerActive = true;
const activeGlobalTimers = { heartbeat: null, watchdog: null, gc: null, resyncBalance: null };

function checkClientHeartbeats() {
    if (!isWssServerActive) return;
    wss.clients.forEach((wsClient) => {
        if (wsClient.isAlive === false) return wsClient.terminate();
        wsClient.isAlive = false;
        try { wsClient.ping(); } catch (e) { wsClient.terminate(); }
    });
    activeGlobalTimers.heartbeat = setTimeout(checkClientHeartbeats, 30000);
}
activeGlobalTimers.heartbeat = setTimeout(checkClientHeartbeats, 30000);

function runTickEngineWatchdog() {
    if (!isWssServerActive) return;
    const agora = Date.now();

    for (const [sessionId, runtime] of sessionRuntimes) {  
        if (runtime.failuresTimeline && runtime.failuresTimeline.length > 0) {  
            runtime.failuresTimeline = runtime.failuresTimeline.filter(t => (agora - t) < CIRCUIT_BREAKER_WINDOW_MS);  
        }  

        if (runtime.tradingState !== STATES.STOPPED && activeDerivSockets.has(sessionId)) {  
            const dWs = activeDerivSockets.get(sessionId);  
            const ultimoPong = runtime.lastDerivPong || runtime.lastTickTime || agora;  
          
            if (agora - ultimoPong > 120000) {  
                console.warn(`[Watchdog Deriv] Conexão estagnada detectada: ${sessionId.slice(0, 8)}`);  
                try { dWs.terminate(); } catch(e){}  
                continue;  
            }  
        }  

        if ([STATES.PROPOSAL, STATES.BUYING].includes(runtime.tradingState)) {  
            if (runtime.stateTimestamp && (agora - runtime.stateTimestamp > 12000)) {  
                runtime.tradingState = STATES.IDLE;  
                runtime.buyInProgress = false;   
                runtime.stateTimestamp = agora;  
            }  
        }  

        if (runtime.tradingState !== STATES.STOPPED && isMongoConfigured && mongoose.connection.readyState === 1) {  
            if (!runtime.lastLeaseUpdate || (agora - runtime.lastLeaseUpdate > LEASE_UPDATE_INTERVAL_MS)) {  
                runtime.lastLeaseUpdate = agora;  
                enfileirarEscritaMongo(sessionId, { $set: { lockTimestamp: agora, serverId: SERVER_INSTANCE_ID } }, false);  
            }  
        }  
    }  
    activeGlobalTimers.watchdog = setTimeout(runTickEngineWatchdog, 4000);
}
activeGlobalTimers.watchdog = setTimeout(runTickEngineWatchdog, 4000);

function runBalanceResyncEngine() {
    if (!isWssServerActive) return;
    for (const [sessionId, dWs] of activeDerivSockets) {
        if (dWs.readyState === WebSocket.OPEN) {
            try {
                dWs.send(JSON.stringify({ balance: 1 }));
            } catch(e){}
        }
    }
    activeGlobalTimers.resyncBalance = setTimeout(runBalanceResyncEngine, 60000);
}
activeGlobalTimers.resyncBalance = setTimeout(runBalanceResyncEngine, 60000);

function runMemoryGarbageCollector() {
    if (!isWssServerActive) return;
    const agora = Date.now();

    for (const [sid, lastAccess] of sessionSaltLastAccess) {  
        if (agora - lastAccess > 1800000) {  
            sessionSalts.delete(sid);  
            sessionSaltLastAccess.delete(sid);  
        }  
    }  
  
    for (const [sessionId, runtime] of sessionRuntimes) {  
        const hasDerivSocket = activeDerivSockets.has(sessionId);  
        const hasClientSocket = activeClientSockets.has(sessionId);  

        if (runtime.tradingState === STATES.STOPPED || runtime.tradingState === STATES.IDLE) {  
            runtime.lastProcessedTickKey = null;  
            runtime.lastProcessedProposalId = null;  
            runtime.failuresTimeline = runtime.failuresTimeline ? runtime.failuresTimeline.slice(-3) : [];  
        }

        if (runtime.proposalsSeenMap && runtime.proposalsSeenMap.size > 0) {
            for (const [propId, timestamp] of runtime.proposalsSeenMap.entries()) {
                if (agora - timestamp > 60000) {
                    runtime.proposalsSeenMap.delete(propId);
                }
            }
        }
      
        if (!hasDerivSocket && !hasClientSocket) {  
            const context = mongoWriteQueues.get(sessionId);  
            if (context && context.queue.length === 0 && !context.processing) {  
                mongoWriteQueues.delete(sessionId);  
            }  

            const ocioso = agora - (runtime.lastAccessed || 0);  
            if (ocioso > 600000) {   
                runtime.history = [];  
                if (runtime.proposalsSeenMap) runtime.proposalsSeenMap.clear();  
            }  

            if (ocioso > 3600000) {   
                if (runtime.tradingState !== STATES.STOPPED) {
                    continue; 
                }
                
                if (clientOrphanTimers.has(sessionId)) {  
                    clearTimeout(clientOrphanTimers.get(sessionId));  
                    clientOrphanTimers.delete(sessionId);  
                }  
                sessionRuntimes.delete(sessionId);  
                sessionSalts.delete(sessionId);   
                sessionSaltLastAccess.delete(sessionId);  
                mongoWriteQueues.delete(sessionId);  
            }  
        }  
    }  
    activeGlobalTimers.gc = setTimeout(runMemoryGarbageCollector, 60000);
}
activeGlobalTimers.gc = setTimeout(runMemoryGarbageCollector, 60000);

function desativarSessaoLocal(userSessionId) {
    const runtime = sessionRuntimes.get(userSessionId);
    if (runtime) {
        runtime.tradingState = STATES.STOPPED;
        runtime.buyInProgress = false;
        runtime.stateTimestamp = Date.now();
        runtime.balanceSynced = false;
    }

    const dWs = activeDerivSockets.get(userSessionId);  
    if (dWs) {  
        if (dWs.readyState === WebSocket.OPEN) {  
            if (runtime?.balanceSubId) { try { dWs.send(JSON.stringify({ forget: runtime.balanceSubId })); } catch(e){} }  
            if (runtime?.contractSubId) { try { dWs.send(JSON.stringify({ forget: runtime.contractSubId })); } catch(e){} }  
            if (runtime?.tickSubId) { try { dWs.send(JSON.stringify({ forget: runtime.tickSubId })); } catch(e){} }  
        }  
        try { dWs.close(); } catch(e){}  
        activeDerivSockets.delete(userSessionId);  
    }  

    limparRecursosSessao(userSessionId);  
  
    enfileirarEscritaMongo(userSessionId, {   
        $set: { botRunning: false, tradingState: STATES.STOPPED, lockTimestamp: 0, serverId: null }   
    }, true);
}

// --- GATEWAY WEBSOCKET CONTROLLER ---
wss.on('connection', (wsReq, httpReq) => {
    const originHeader = httpReq.headers.origin;
    const isVercelValidProject = typeof originHeader === 'string' && VERCEL_PREVIEW_REGEX.test(originHeader);

    if (!originHeader || (!ALLOWED_ORIGINS.includes(originHeader) && !isVercelValidProject)) {  
        wsReq.close(4401, 'Origem não autorizada');  
        return;  
    }  

    if (activeClientSockets.size >= MAX_ACTIVE_CLIENTS) {  
        wsReq.close(4429, 'Capacidade de infraestrutura esgotada');  
        return;  
    }  

    wsReq.isAlive = true;  
    wsReq.on('pong', () => { wsReq.isAlive = true; });  

    let userSessionId = null;  

    wsReq.on('message', async (message) => {  
        try {  
            const raw = message.toString();  
            if (raw.length > MAX_WS_PAYLOAD_BYTES) return wsReq.close();  

            let data;  
            try { data = JSON.parse(raw); } catch(jsonErr) {  
                if (wsReq.readyState === WebSocket.OPEN) {  
                    wsReq.send(JSON.stringify({ type: 'ERROR', message: 'Payload inválido.' }));  
                }  
                return;  
            }  
          
            if (data.action === 'PING') return wsReq.send(JSON.stringify({ type: 'PONG' }));  

            if (data.action === 'INIT') {  
                userSessionId = data.sessionId;  
              
                if (typeof userSessionId !== 'string' || !UUID_REGEX.test(userSessionId)) {  
                    return wsReq.close();  
                }  
              
                if (clientOrphanTimers.has(userSessionId)) {  
                    clearTimeout(clientOrphanTimers.get(userSessionId));  
                    clientOrphanTimers.delete(userSessionId);  
                }  

                let activeSalt = null;  
                if (sessionSalts.has(userSessionId)) {  
                    activeSalt = sessionSalts.get(userSessionId);  
                    sessionSaltLastAccess.set(userSessionId, Date.now());  
                } else if (isMongoConfigured && mongoose.connection.readyState === 1 && SessionModel) {  
                    const doc = await SessionModel.findById(userSessionId).maxTimeMS(5000);  
                    if (doc && doc.sessionSalt) {  
                        activeSalt = doc.sessionSalt;  
                        sessionSalts.set(userSessionId, activeSalt);  
                        sessionSaltLastAccess.set(userSessionId, Date.now());  
                    }  
                }  

                if (!activeSalt || !data.timestamp || Date.now() - parseInt(data.timestamp, 10) > 300000) {  
                    return wsReq.close();  
                }  

                if (data.signature !== gerarAssinaturaSessao(userSessionId, activeSalt, data.timestamp)) {  
                    return wsReq.close();  
                }  
              
                activeClientSockets.set(userSessionId, wsReq);  
              
                if (!sessionRuntimes.has(userSessionId)) {  
                    const dbState = await buscarSessao(userSessionId);  
                    if (dbState && !dbState.refreshToken) {  
                        wsReq.send(JSON.stringify({ type: 'ERROR', message: 'Credenciais expiradas.' }));  
                        return;  
                    }  
                    const estadoRestaurado = dbState?.tradingState === STATES.STOPPED ? STATES.STOPPED : (dbState?.tradingState || STATES.IDLE);  
                    
                    // Inicialização segura de estrutura caso necessário
                    sessionRuntimes.set(userSessionId, {
                        token: dbState.accessToken,
                        refreshToken: dbState.refreshToken,
                        expiresAt: dbState.expiresAt,
                        tradingState: estadoRestaurado,
                        buyInProgress: false,
                        tradeVersion: 0,
                        failuresTimeline: [],
                        proposalsSeenMap: new Map(),
                        history: [],
                        config: dbState.config || { stake: 1.0 }
                    });

                    if (estadoRestaurado !== STATES.STOPPED) {
                        inicializarBotDeriv(userSessionId);
                    }
                }
                
                wsReq.send(JSON.stringify({ type: 'INIT_OK', state: sessionRuntimes.get(userSessionId).tradingState }));
            }  
        } catch (err) {  
            if (wsReq.readyState === WebSocket.OPEN) {
                wsReq.send(JSON.stringify({ type: 'ERROR', message: 'Erro interno.' }));
            }
        }  
    });  

    wsReq.on('close', () => {  
        if (userSessionId) {  
            activeClientSockets.delete(userSessionId);  
            // Se o bot estiver parado, limpa a sessão da RAM após um tempo órfão
            const runtime = sessionRuntimes.get(userSessionId);  
            if (runtime && runtime.tradingState === STATES.STOPPED) {  
                const timer = setTimeout(() => {  
                    desativarSessaoLocal(userSessionId);  
                }, 60000);  
                clientOrphanTimers.set(userSessionId, timer);  
            }  
        }  
    });  
});

// --- SHUTDOWN GRACIOSO INDUSTRIAL ---
async function executarGracefulShutdown(motivo) {
    if (isShuttingDown) return;
    isShuttingDown = true;
    isWssServerActive = false;

    console.log(`[SHUTDOWN] Iniciando rotina motivada por: ${motivo}`);

    // Desativa temporizadores globais
    clearTimeout(activeGlobalTimers.heartbeat);
    clearTimeout(activeGlobalTimers.watchdog);
    clearTimeout(activeGlobalTimers.gc);
    clearTimeout(activeGlobalTimers.resyncBalance);

    // Fecha conexões com clientes locais de gateway
    wss.close(() => {
        console.log('[SHUTDOWN] Servidor Gateway WebSocket fechado.');
    });

    // Correção Estrutural de Referência Cruzada e Limpeza Limpa do Fernando
    for (const [sid, dWs] of activeDerivSockets.entries()) {
        limparRecursosSessao(sid);
        try {
            if (dWs.readyState === WebSocket.OPEN) {
                dWs.close();
            }
        } catch (e) {
            console.error(`[SHUTDOWN] Erro ao fechar dWs de ${sid}:`, e.message);
        }
        activeDerivSockets.delete(sid); // Removido do mapa garantindo morte de referências
    }

    // Processamento e esvaziamento sequencial de filas remanescentes do MongoDB
    if (isMongoConfigured && mongoWriteQueues.size > 0) {
        console.log(`[SHUTDOWN] Forçando flush de ${mongoWriteQueues.size} filas do banco de dados...`);
        for (const sid of mongoWriteQueues.keys()) {
            const context = mongoWriteQueues.get(sid);
            if (context && context.queue.length > 0) {
                const container = context.queue[context.queue.length - 1];
                try {
                    await SessionModel.findByIdAndUpdate(sid, container.payload, { upsert: true });
                } catch (dbErr) {
                    console.error(`[SHUTDOWN] Erro no flush emergencial de ${sid}:`, dbErr.message);
                }
            }
        }
    }

    if (isMongoConfigured) {
        try {
            await mongoose.disconnect();
            console.log('[SHUTDOWN] Ligação com MongoDB desfeita.');
        } catch (mErr) {
            console.error('[SHUTDOWN] Erro ao desconectar base de dados:', mErr.message);
        }
    }

    server.close(() => {
        console.log('[SHUTDOWN] Cluster finalizado com segurança total.');
        process.exit(0);
    });

    setTimeout(() => {
        console.error('[SHUTDOWN] Tempo limite estourado. Forçando terminação severa.');
        process.exit(1);
    }, 20000);
}

process.on('SIGTERM', () => executarGracefulShutdown('SIGTERM'));
process.on('SIGINT', () => executarGracefulShutdown('SIGINT'));

// --- INICIALIZAÇÃO DA PORTA DE REDE ---
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
    console.log(`[Engine v9] Executando sob ID de Instância: ${SERVER_INSTANCE_ID} na porta ${PORT}`);
});
