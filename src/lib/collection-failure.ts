export function collectionFailure(summary: string | null | undefined): string {
  const message = summary ?? "";
  if (/ERR_TLS_CERT_ALTNAME_INVALID/i.test(message)) return "O endereço configurado não corresponde ao certificado. Use um endereço válido no certificado ou emita um certificado para esse endereço.";
  if (/CERT_HAS_EXPIRED/i.test(message)) return "O certificado da origem expirou. Renove o certificado para retomar a coleta.";
  if (/SELF_SIGNED|UNABLE_TO_VERIFY|CERT_AUTHORITY|DEPTH_ZERO/i.test(message)) return "Não foi possível validar o certificado da origem. Confira o certificado CA cadastrado nesta integração.";
  if (/HTTP 401/i.test(message)) return "A origem recusou as credenciais. Confira o usuário e a senha desta empresa.";
  if (/HTTP 403/i.test(message)) return "A conta não tem permissão para consultar os dados. Confira as permissões desta empresa na origem.";
  if (/finish.*HTTP 5\d\d/i.test(message)) return "Os dados foram recebidos, mas o banco não concluiu a publicação. A coleta fará uma nova tentativa automaticamente.";
  if (/TIMEOUT|ETIMEDOUT|ECONN|ENETUNREACH|EHOSTUNREACH|ENOTFOUND|EAI_AGAIN/i.test(message)) return "O coletor não conseguiu acessar a origem. Confira o endereço, a porta e o acesso à rede. A coleta fará uma nova tentativa automaticamente.";
  if (/HTTP 429|HTTP 5\d\d/i.test(message)) return "Um serviço está temporariamente indisponível ou limitou as requisições. A coleta fará uma nova tentativa automaticamente.";
  return "A coleta não foi concluída. Confira a configuração desta integração e o acesso do coletor à origem.";
}
