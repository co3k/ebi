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
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const container = env.EBI_SERVER.getByName("singleton");
    await container.startAndWaitForPorts();
    return container.fetch(request);
  },
} satisfies ExportedHandler<Env>;
