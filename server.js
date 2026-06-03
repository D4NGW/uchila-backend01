// server.js
const express = require('express');
const cors = require('cors');

const app = express();

// Evita o erro de CORS para permitir que a Vercel converse com o Render
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST']
}));

app.use(express.json());

// O seu ID alfanumérico atuando como CLIENT_ID no servidor do OAuth
const CLIENT_ID = "33nZb90yOHPIJXVFbYG39";

app.get('/', (req, res) => {
    res.send('Servidor de Autenticação do UchilaBot operando normalmente.');
});

// Rota para trocar o 'code' temporário pelo token de acesso final
app.post('/api/trocar-token', async (req, res) => {
    const { code, code_verifier, redirect_uri } = req.body;

    if (!code || !code_verifier || !redirect_uri) {
        return res.status(400).json({ error: "Parâmetros de autenticação em falta." });
    }

    try {
        // Chamada oficial à Deriv para conversão do código em token
        const derivResponse = await fetch('https://auth.deriv.com/oauth2/token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                grant_type: 'authorization_code',
                code: code,
                client_id: CLIENT_ID, // Enviado como client_id exigido pelo protocolo OAuth
                code_verifier: code_verifier,
                redirect_uri: redirect_uri
            })
        });

        const data = await derivResponse.json();

        if (data.error) {
            return res.status(400).json({ error: data.error_description || data.error });
        }

        // Devolve o token de acesso para o Front-end
        return res.json({
            access_token: data.access_token
        });

    } catch (error) {
        console.error("Erro interno no servidor do Render:", error);
        return res.status(500).json({ error: "Erro na comunicação com a API da Deriv." });
    }
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`Servidor rodando com sucesso na porta ${PORT}`);
});