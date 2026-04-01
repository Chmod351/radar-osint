/**
 * Limpia cualquier entrada (URL, Host con basura, etc.) 
 * para dejar solo el Host puro.
 */
export function normalizeTarget(input: string): string {
  if (!input) return "";

  let clean = input.trim().toLowerCase();

  // 1. Eliminar protocolos (http://, https://, ftp://, etc.)
  clean = clean.replace(/^(?:f|ht)tps?:\/\//, "");

  // 2. Eliminar el path, query strings o puertos (dominio.com/admin?id=1 -> dominio.com)
  clean = clean.split('/')[0].split('?')[0].split(':')[0];

  // 3. Eliminar el 'www.' inicial si existe
  // Usamos una regex que solo pegue al principio
  clean = clean.replace(/^www\./, "");

  return clean;
}
