# Receber alertas do n8n

O endpoint recebe alertas SOC sem misturá-los aos achados de vulnerabilidade. Cada chave pertence a uma empresa. A empresa é resolvida pela chave no servidor; não envie `tenant_id` no corpo.

## Configuração

1. Abra **Administração → Integrações → Alertas do n8n**.
2. Selecione a empresa ativa e dê um nome à chave. Gere uma chave por ambiente/fluxo do n8n.
3. Copie a chave quando ela aparecer. Ela é mostrada uma única vez. Para trocar, crie outra, atualize o n8n e revogue a antiga.
4. No n8n, use um nó **HTTP Request**, método `POST`, com o endpoint exibido na tela.
5. Configure estes cabeçalhos:

   - `Content-Type: application/json`
   - `Authorization: Bearer <chave-pv_soc_...>`
   - `apikey: <chave-publica-do-projeto>`

A chave pública é a publishable key do projeto. A chave `pv_soc_...` é secreta; guarde-a em credencial do n8n e não em URL, dados fixados do fluxo ou logs.

## Corpo

Envie de 1 a 100 alertas por requisição. A requisição inteira deve ter até 1 MB.

```json
{
  "events": [
    {
      "source_id": "firewall-filial-01",
      "source_name": "Firewall Filial 01",
      "source_category": "firewall",
      "source_vendor": "vendor",
      "source_product": "product",
      "source_event_id": "2026-10-30:index-or-stream:document-id",
      "source_index": "alerts-2026.10.30",
      "source_document_id": "document-id",
      "occurred_at": "2026-10-30T14:30:00Z",
      "severity": "high",
      "severity_original": "7",
      "title": "Bloqueio de conexão",
      "message": "Descrição recebida da origem",
      "rule_id": "regra-42",
      "rule_description": "Descrição da regra",
      "rule_level": 10,
      "agent_id": "001",
      "agent_name": "servidor-01",
      "src_ip": "203.0.113.10",
      "dst_ip": "192.0.2.15",
      "dst_port": 443,
      "network_protocol": "tcp",
      "source_action": "deny",
      "normalized_action": "blocked",
      "mitre_ids": ["T1110"],
      "mitre_tactics": ["Credential Access"],
      "mitre_techniques": ["Brute Force"],
      "raw_payload": {"event_type": "example"}
    }
  ]
}
```

Campos obrigatórios por evento: `source_id`, `source_name`, `source_event_id`, `occurred_at`, `severity` e `title`. As severidades aceitas são `critical`, `high`, `medium`, `low`, `informational` e `unknown`. Use `unknown` quando a origem não permite uma classificação confiável e guarde o valor original em `severity_original`.

`source_id` deve permanecer igual para uma mesma fonte. `source_event_id` deve identificar o documento original de forma estável. Para eventos de índice, use uma composição como `índice + _id` da origem. Os dois juntos formam a chave de deduplicação por empresa. Reenvios retornam como duplicados e não aumentam os totais.

Envie `occurred_at` em ISO 8601 com fuso horário explícito, preferencialmente UTC (`Z`). A entrada aceita eventos dos últimos 30 dias e tolera até 5 minutos no futuro; eventos mais antigos são recusados para manter reenvios idempotentes após a expiração dos detalhes. Não substitua horário ausente por horário de processamento. `raw_payload` é opcional, deve ser um objeto de até 4 KB e deve conter apenas campos necessários; os campos normalizados continuam sendo a fonte da interface.

## Respostas

- `200`: `accepted`, `inserted` e `duplicates` informam o resultado do lote. `accepted` é a quantidade recebida, `inserted` a quantidade nova e `duplicates` a quantidade já recebida antes.
- `400`: JSON, lote ou campo inválido; não repita sem corrigir os dados.
- `401`: chave ausente, inválida ou revogada.
- `403`: empresa inativa; o lote não foi armazenado.
- `413`: corpo acima de 1 MB.
- `503`: indisponibilidade temporária ao confirmar a empresa; tente novamente com o mesmo lote.

## Retenção e volume

Os detalhes ficam por 30 dias. Uma rotina horária remove até 5.000 registros vencidos por execução. Totais compactos por dia UTC e severidade ficam preservados. Os contadores só são atualizados para um alerta novo, então reenvio idempotente não altera o total histórico dentro da janela de ingestão de 30 dias. A tela não calcula MTTD, MTTA, MTTR ou estado de incidente sem receber os eventos de ciclo de vida necessários.
