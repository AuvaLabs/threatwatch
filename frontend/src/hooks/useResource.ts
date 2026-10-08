import { useEffect, useState } from "preact/hooks";

export interface Resource<T> {
  data: T | null;
  error: string | null;
  loading: boolean;
}

export function useResource<T>(loader: (signal: AbortSignal) => Promise<T>, dependencies: unknown[] = []): Resource<T> {
  const [resource, setResource] = useState<Resource<T>>({ data: null, error: null, loading: true });

  useEffect(() => {
    const controller = new AbortController();
    setResource((current) => ({ ...current, error: null, loading: true }));
    loader(controller.signal)
      .then((data) => setResource({ data, error: null, loading: false }))
      .catch((error: unknown) => {
        if (controller.signal.aborted) return;
        const message = error instanceof Error ? error.message : "Unexpected request failure";
        setResource({ data: null, error: message, loading: false });
      });
    return () => controller.abort();
  }, dependencies);

  return resource;
}
