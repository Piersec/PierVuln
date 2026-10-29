# Coletor de ativos no host Docker

Este contêiner lê do site as integrações ativas e a configuração criptografada da API de ativos. A cada 15 minutos, busca os agentes em páginas de 500 e envia um snapshot para o Supabase. A VPN do computador não participa da coleta.

Implante uma vez no host Docker que alcança a API privada:

```sh
cd /caminho/para/PierVuln
export SUPABASE_URL=https://SEU-PROJETO.supabase.co
export SUPABASE_PUBLISHABLE_KEY=CHAVE_PUBLICAVEL
export WAZUH_WORKER_CONFIG_TOKEN=SEGREDO_DO_WORKER_CONFIG
docker compose -f connector/assets/docker-compose.yml up -d --build
```

Use o mesmo `WAZUH_WORKER_CONFIG_TOKEN` configurado na função de configuração do coletor. No site, abra **Administração → Integrações** e clique em **Configurar API do Manager** no cartão da integração. Informe endpoint HTTPS, usuário, senha e certificado CA público, se necessário. O nome do endpoint deve corresponder ao certificado TLS. Use as credenciais da API, não o login da VPN. O site guarda as credenciais criptografadas e o coletor recebe a configuração automaticamente.

O token de configuração não é a senha da API. Guarde-o somente no ambiente do contêiner.
