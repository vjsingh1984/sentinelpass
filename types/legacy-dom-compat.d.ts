interface EventTarget {
  action?: string;
  id?: string;
  dataset?: DOMStringMap;
  value?: any;
  form?: HTMLFormElement | null;
  closest?: (selectors: string) => Element | null;
  querySelector?: (selectors: string) => Element | null;
}

interface Element {
  value?: any;
  disabled?: boolean;
  readOnly?: boolean;
  form?: HTMLFormElement | null;
}

interface HTMLElement {
  value?: any;
  disabled?: boolean;
  readOnly?: boolean;
  type?: string;
}
