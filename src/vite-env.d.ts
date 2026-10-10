/// <reference types="vite/client" />

declare module 'https://*' {
  export const loadPyodide: (options?: any) => Promise<any>;
  const content: any;
  export default content;
}
