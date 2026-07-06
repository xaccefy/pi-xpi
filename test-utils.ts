export class MockExtensionAPI {
  // biome-ignore lint/suspicious/noExplicitAny: generic tools array
  tools: any[] = [];
  // biome-ignore lint/suspicious/noExplicitAny: generic tools array
  commands: Record<string, any> = {};
  // biome-ignore lint/suspicious/noExplicitAny: generic tools array
  events: Record<string, ((...args: any[]) => any)[]> = {};

  // biome-ignore lint/suspicious/noExplicitAny: generic tools array
  registerTool(spec: any) {
    this.tools.push(spec);
  }

  // biome-ignore lint/suspicious/noExplicitAny: generic tools array
  registerCommand(name: string, spec: any) {
    this.commands[name] = spec;
  }

  // biome-ignore lint/suspicious/noExplicitAny: generic tools array
  on(event: string, handler: (...args: any[]) => any) {
    if (!this.events[event]) this.events[event] = [];
    this.events[event].push(handler);
  }

  // biome-ignore lint/suspicious/noExplicitAny: generic tools array
  async emit(event: string, ...args: any[]) {
    const handlers = this.events[event] || [];
    for (const h of handlers) {
      await h(...args);
    }
  }
}
