export function isReadOnlyMethod(method: string): boolean {
  return ['GET', 'HEAD', 'OPTIONS'].includes(method.toUpperCase())
}

export function mutationRequiresCredentials(method: string, token: string): boolean {
  return !isReadOnlyMethod(method) && token.trim().length === 0
}
