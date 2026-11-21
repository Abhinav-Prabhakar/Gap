import type { AuthProvider } from "gapmcp-core";

/**
 * Try providers in order and return the first non-null authentication result.
 *
 * `challenge` and `protectedResourceMetadata` are taken from the first provider
 * that defines them, so a composed provider advertises a single coherent
 * discovery document.
 */
export function composeAuth(...providers: AuthProvider[]): AuthProvider {
  const composed: AuthProvider = {
    async authenticate(request) {
      for (const provider of providers) {
        const result = await provider.authenticate(request);
        if (result) return result;
      }
      return null;
    },
  };

  const challengeProvider = providers.find(
    (provider) => typeof provider.challenge === "function",
  );
  if (challengeProvider) {
    composed.challenge = () => challengeProvider.challenge!();
  }

  const metadataProvider = providers.find(
    (provider) => typeof provider.protectedResourceMetadata === "function",
  );
  if (metadataProvider) {
    composed.protectedResourceMetadata = () =>
      metadataProvider.protectedResourceMetadata!();
  }

  return composed;
}
