export function signInNotice(error: { status?: number; code?: string; name?: string }): string {
  if (error.code === "captcha_failed") return "O desafio de segurança expirou ou já foi utilizado. Aguarde a nova confirmação e tente entrar novamente.";
  if (error.status === 429 || error.code === "over_request_rate_limit") return "Muitas tentativas de acesso. Aguarde alguns instantes antes de tentar novamente.";
  if ((error.status ?? 0) >= 500 || error.code === "request_timeout" || error.name === "AuthRetryableFetchError") return "O serviço de login está temporariamente indisponível. Aguarde alguns instantes e tente novamente.";
  return "Não foi possível entrar. Confira o e-mail e a senha.";
}
