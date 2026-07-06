export class MockExtensionAPI {
  tools: any[] = [];
  commands: Record<string, any> = {};
  events: Record<string, Function[]> = {};

  registerTool(spec: any) {
    this.tools.push(spec);
  }

  registerCommand(name: string, spec: any) {
    this.commands[name] = spec;
  }

  on(event: string, handler: Function) {
    if (!this.events[event]) this.events[event] = [];
    this.events[event].push(handler);
  }

  async emit(event: string, ...args: any[]) {
    const handlers = this.events[event] || [];
    for (const h of handlers) {
      await h(...args);
    }
  }
}
