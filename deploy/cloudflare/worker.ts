import { Container } from "@cloudflare/containers";

type EbiContainerEnv = Env & {
  EBI_LOG_KEY?: string;
  EBI_WITNESS_KEYS?: string;
  EBI_WITNESS_URLS?: string;
  EBI_REQUIRED_WITNESSES?: string;
  EBI_STORAGE_ENDPOINT?: string;
  EBI_STORAGE_BUCKET?: string;
  EBI_STORAGE_ACCESS_KEY?: string;
  EBI_STORAGE_SECRET_KEY?: string;
};

const containerEnvKeys = [
  "EBI_PORT",
  "EBI_DATA_DIR",
  "EBI_CHECKPOINT_STATE",
  "EBI_LOG_ORIGIN",
  "EBI_LOG_KEY",
  "EBI_WITNESS_KEYS",
  "EBI_WITNESS_URLS",
  "EBI_REQUIRED_WITNESSES",
  "EBI_STORAGE",
  "EBI_STORAGE_ENDPOINT",
  "EBI_STORAGE_REGION",
  "EBI_STORAGE_BUCKET",
  "EBI_STORAGE_ACCESS_KEY",
  "EBI_STORAGE_SECRET_KEY",
  "EBI_STORAGE_PATH_STYLE",
] as const;

const checkpointStateKey = "checkpoint-state-v1";

function toBase64(data: ArrayBuffer): string {
  const bytes = new Uint8Array(data);
  let binary = "";
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
  }
  return btoa(binary);
}

/**
 * Thin Cloudflare Worker glue. All ebi security logic remains in the
 * Go container. A fixed Durable Object name enforces a single sequencer. The
 * constructor explicitly forwards only the allow-listed Worker vars/secrets;
 * bindings and unrelated platform metadata never enter the container.
 */
export class EbiServer extends Container<EbiContainerEnv> {
  defaultPort = 8080;
  requiredPorts = [8080];
  sleepAfter = "5m";
  enableInternet = true;
  pingEndpoint = "/healthz";

  constructor(ctx: DurableObjectState<{}>, env: EbiContainerEnv) {
    super(ctx, env);
    this.envVars = Object.fromEntries(
      containerEnvKeys.flatMap((key) => {
        const value = env[key];
        return typeof value === "string" && value !== "" ? [[key, value]] : [];
      }),
    );
  }

  private async startWithCheckpointState(): Promise<void> {
    const checkpoint = await this.ctx.storage.get<string>(checkpointStateKey);
    const envVars = { ...(this.envVars ?? {}) };
    if (checkpoint) {
      envVars.EBI_CHECKPOINT_STATE_B64 = checkpoint;
    }
    await this.startAndWaitForPorts({
      startOptions: { envVars },
    });
  }

  private async persistCheckpointState(): Promise<void> {
    const runtime = this.ctx.container;
    if (!runtime?.running) {
      return;
    }
    const path = this.envVars?.EBI_CHECKPOINT_STATE ?? "/tmp/ebi/checkpoint-state";
    const process = await runtime.exec(
      ["/ebi-server", "checkpoint-state", "export", "--path", path],
      { stdout: "pipe", stderr: "pipe" },
    );
    const output = await process.output();
    if (output.exitCode !== 0) {
      const message = new TextDecoder().decode(output.stderr).trim();
      throw new Error(`checkpoint-state export failed: ${message || output.exitCode}`);
    }
    if (output.stdout.byteLength === 0) {
      return;
    }
    await this.ctx.storage.put(checkpointStateKey, toBase64(output.stdout));
  }

  override async fetch(request: Request): Promise<Response> {
    await this.startWithCheckpointState();
    const response = await super.fetch(request);
    if (request.method !== "POST") {
      return response;
    }
    const body = await response.arrayBuffer();
    await this.persistCheckpointState();
    return new Response(body, {
      status: response.status,
      statusText: response.statusText,
      headers: response.headers,
    });
  }

  override async onActivityExpired(): Promise<void> {
    await this.persistCheckpointState();
    await super.onActivityExpired();
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const container = env.EBI_SERVER.getByName("singleton");
    return container.fetch(request);
  },
} satisfies ExportedHandler<Env>;
