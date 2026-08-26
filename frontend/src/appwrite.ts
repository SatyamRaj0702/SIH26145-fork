import { Client, Databases } from "appwrite";
import type { Alert } from "./types";

const endpoint = (import.meta.env.VITE_APPWRITE_ENDPOINT as string | undefined)?.trim() || "";
const projectId = (import.meta.env.VITE_APPWRITE_PROJECT_ID as string | undefined)?.trim() || "";
const databaseId = (import.meta.env.VITE_APPWRITE_DATABASE_ID as string | undefined)?.trim() || "";
const collectionId = (import.meta.env.VITE_APPWRITE_ALERTS_COLLECTION_ID as string | undefined)?.trim() || "";

// Prefer an explicit endpoint; otherwise fall back to the dashboard origin so
// the Vite dev proxy (and any reverse proxy) can forward /v1 to Appwrite.
const resolvedEndpoint = (endpoint || `${window.location.origin}/v1`).replace(/\/v1\/?$/, "");

export const appwriteConfigured = Boolean(projectId && databaseId && collectionId);

let client: Client | null = null;
let databases: Databases | null = null;

if (appwriteConfigured) {
  client = new Client()
    .setEndpoint(resolvedEndpoint)
    .setProject(projectId);
  databases = new Databases(client);
}

export const alertsChannel = (): string =>
  `databases.${databaseId}.collections.${collectionId}.documents`;

const toAlert = (document: Record<string, unknown>): Alert => {
  const { $id, $createdAt: _createdAt, $updatedAt: _updatedAt, ...rest } = document;
  return {
    alert_id: String($id ?? rest.alert_id ?? ""),
    ...(rest as unknown as Omit<Alert, "alert_id">),
  };
};

export interface AppwriteRealtime {
  unsubscribe: () => void;
}

export const subscribeAlerts = (
  onAlert: (alert: Alert) => void,
  onError: (message: string) => void,
): AppwriteRealtime | null => {
  if (!client) return null;
  let unsubscribe: (() => void) | null = null;
  try {
    unsubscribe = client.subscribe(alertsChannel(), (response) => {
      const events = response.events ?? [];
      if (!events.some((event) => event.includes("create"))) return;
      const payload = response.payload as Record<string, unknown> | undefined;
      if (payload?.alert_id) onAlert(toAlert(payload));
    });
  } catch (error) {
    onError(error instanceof Error ? error.message : "Appwrite realtime subscription failed");
    return null;
  }
  return { unsubscribe: () => unsubscribe?.() };
};

export const listStoredAlerts = async (limit = 100): Promise<Alert[]> => {
  if (!databases) return [];
  const result = await databases.listDocuments(databaseId, collectionId, [`limit(${limit})`]);
  return (result.documents ?? []).map((document) => toAlert(document as unknown as Record<string, unknown>));
};
