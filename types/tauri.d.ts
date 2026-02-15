type InvokeFn = <T = unknown>(cmd: string, args?: Record<string, unknown>) => Promise<T>;

interface Window {
  __TAURI__?: {
    core: {
      invoke: InvokeFn;
    };
    dialog: {
      confirm: (message: string, options?: Record<string, unknown>) => Promise<boolean>;
    };
    clipboardManager: {
      writeText: (text: string) => Promise<void>;
      readText: () => Promise<string>;
    };
  };
}
