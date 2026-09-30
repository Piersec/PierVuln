# Notificações gerais do site

Ampliação solicitada em 30/09/2026. O componente visual continua o mesmo: toast temporário, sem pílula fixa quando não existem avisos.

| Área | Avisos |
| --- | --- |
| Navegação | Troca entre as áreas existentes do site, sem aviso ao abrir a primeira página. |
| Conexão | Perda e retorno da internet; indisponibilidade e recuperação do canal privado do Supabase. |
| Formulários | Campos obrigatórios ou inválidos ao tentar enviar; erros de acesso e recuperação. Não mostra conteúdo de senha ou segredo. |
| Acesso | Entrada confirmada, sessão encerrada, falha ao sair, link de recuperação validado ou expirado, senha atualizada e cadastro concluído. |
| Vulnerabilidades | Troca de empresa, severidade, busca e página; atualização iniciada, concluída ou falha; abertura e fechamento de detalhes; erros ao carregar comentários e histórico; alteração de fluxo; comentário publicado ou nota interna salva. |
| Book dos Clientes | Troca de empresa; atualização iniciada e relatório atualizado com contagem real; erros de consulta de relatório, fontes, vínculos e sincronização. |
| Administração | Busca, status, empresa/equipe e paginação; formulário aberto ou fechado; atualização iniciada/concluída; erros de carregamento; ações administrativas existentes, preparação de download e cópia do segredo. |
| Banco | Eventos administrativos já configurados no canal privado; continuam disponíveis apenas à equipe Pier. |
| Falhas inesperadas | Rejeição não tratada de operação assíncrona, com mensagem genérica sem detalhes técnicos ou dados sensíveis. |

Buscas e seleções aguardam 600 ms sem novas alterações antes do aviso. Eventos com a mesma chave atualizam o aviso existente. A fila tem até oito avisos e preserva o que está sendo lido, priorizando erros sobre atualizações informativas pendentes. O segredo fica no diálogo próprio e nunca entra no conteúdo do toast.

## Validação

TypeScript e testes da renderização, parser e fila executados. Os novos testes verificam limite da fila em rajadas, preservação do aviso visível e prioridade de erros. Build de produção executado com todas as rotas.

No navegador local, enviar o formulário de login vazio exibiu o toast de validação sem realizar login. A pílula desapareceu automaticamente, confirmado pela ausência do elemento no DOM. Navegar de login para recuperação exibiu o aviso correspondente à área selecionada. Captura do teste salva como `notificacoes-ampliadas.png` na pasta de visualizações da conversa.

Não foram alterados clientes, senhas ou permissões para testar estes avisos. A validação manual de produção não substitui os testes: login, envio de e-mail, clipboard e eventos de conexão precisam das condições reais correspondentes para serem exercitados.

## Revisão visual

PASS: paleta, tipografia, dimensões, contraste e controles da pílula existente preservados; nenhuma imagem, estatística ou navegação fictícia adicionada. PASS: avisos continuam com fechamento automático, dispensar e pausa para leitura. PASS: textos nomeiam ações concretas; contagem do relatório vem da consulta concluída. A revisão visual anterior e suas limitações permanecem em `admin-panel-validation.md`.
