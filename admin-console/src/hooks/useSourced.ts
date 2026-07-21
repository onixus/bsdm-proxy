import { useQuery, type UseQueryResult } from '@tanstack/react-query'
import type { Sourced } from '../api/source'

/**
 * Query wrapper for provenance-aware fetchers. Keeps the last good result on
 * refetch errors (placeholderData) so panels degrade to "stale" rather than
 * flashing empty.
 */
export function useSourcedQuery<T>(
  key: readonly unknown[],
  fetcher: () => Promise<Sourced<T>>,
  opts?: { refetchInterval?: number | false; enabled?: boolean },
): UseQueryResult<Sourced<T>, Error> {
  return useQuery<Sourced<T>, Error>({
    queryKey: key,
    queryFn: fetcher,
    refetchInterval: opts?.refetchInterval ?? false,
    enabled: opts?.enabled ?? true,
  })
}
