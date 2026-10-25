// CodeMirror 6 wrapper (SPEC §7.4 editor). Loaded lazily with the editor page.
import { defaultKeymap, history, historyKeymap, indentWithTab } from "@codemirror/commands";
import {
  bracketMatching,
  foldGutter,
  foldKeymap,
  HighlightStyle,
  indentOnInput,
  indentUnit,
  StreamLanguage,
  syntaxHighlighting,
} from "@codemirror/language";
import { highlightSelectionMatches, search, searchKeymap } from "@codemirror/search";
import { Compartment, EditorState, type Extension } from "@codemirror/state";
import {
  drawSelection,
  EditorView,
  highlightActiveLine,
  highlightActiveLineGutter,
  highlightSpecialChars,
  keymap,
  lineNumbers,
} from "@codemirror/view";
import { tags } from "@lezer/highlight";
import { forwardRef, useEffect, useImperativeHandle, useRef } from "react";

export interface CodeEditorHandle {
  getText: () => string;
  setText: (s: string) => void;
  focus: () => void;
}

interface Props {
  initial: string;
  path: string;
  wrap: boolean;
  tabSize: number; // 0 = tabs
  readOnly: boolean;
  label: string;
  onDirty: () => void;
  onSave: () => void;
  onCursor: (line: number, col: number) => void;
}

/** Picks a language by file name/path; legacy (stream) modes cover config formats. */
export async function languageFor(path: string): Promise<Extension | null> {
  const base = path.slice(path.lastIndexOf("/") + 1).toLowerCase();
  const ext = base.includes(".") ? base.slice(base.lastIndexOf(".") + 1) : "";
  const legacy = async (load: () => Promise<Parameters<typeof StreamLanguage.define>[0]>) => StreamLanguage.define(await load());
  if (ext === "json" || ext === "jsonc") return (await import("@codemirror/lang-json")).json();
  if (ext === "yaml" || ext === "yml") return (await import("@codemirror/lang-yaml")).yaml();
  if (ext === "py") return (await import("@codemirror/lang-python")).python();
  if (["js", "mjs", "cjs", "jsx", "ts", "tsx", "mts", "cts"].includes(ext)) {
    const { javascript } = await import("@codemirror/lang-javascript");
    return javascript({ typescript: ext.includes("t") && ext !== "cjs", jsx: ext.endsWith("x") });
  }
  if (ext === "md" || ext === "markdown") return (await import("@codemirror/lang-markdown")).markdown();
  if (ext === "sql") return (await import("@codemirror/lang-sql")).sql();
  if (["xml", "svg", "xsd", "xsl", "xslt", "plist", "html", "htm"].includes(ext)) return (await import("@codemirror/lang-xml")).xml();
  if (ext === "toml") return legacy(async () => (await import("@codemirror/legacy-modes/mode/toml")).toml);
  if (base === "dockerfile" || base === "containerfile" || ext === "dockerfile")
    return legacy(async () => (await import("@codemirror/legacy-modes/mode/dockerfile")).dockerFile);
  if (ext === "diff" || ext === "patch") return legacy(async () => (await import("@codemirror/legacy-modes/mode/diff")).diff);
  if ((path.includes("/nginx/") && (ext === "conf" || !ext)) || base === "nginx.conf")
    return legacy(async () => (await import("@codemirror/legacy-modes/mode/nginx")).nginx);
  if (
    ["sh", "bash", "zsh", "ksh"].includes(ext) ||
    [".bashrc", ".profile", ".bash_profile", ".bash_logout", ".zshrc", "crontab"].includes(base) ||
    path.includes("/cron.")
  )
    return legacy(async () => (await import("@codemirror/legacy-modes/mode/shell")).shell);
  if (
    ["ini", "conf", "cfg", "cnf", "properties", "env", "service", "socket", "timer", "mount", "automount", "path", "target", "slice", "network", "netdev", "link"].includes(ext) ||
    base === ".env"
  )
    return legacy(async () => (await import("@codemirror/legacy-modes/mode/properties")).properties);
  return null;
}

const highlight = HighlightStyle.define([
  { tag: [tags.keyword, tags.controlKeyword, tags.moduleKeyword, tags.operatorKeyword], color: "var(--violet-text)" },
  { tag: [tags.comment, tags.lineComment, tags.blockComment], color: "var(--text-faint)", fontStyle: "italic" },
  { tag: [tags.string, tags.special(tags.string), tags.regexp], color: "var(--success)" },
  { tag: [tags.number, tags.bool, tags.null, tags.atom], color: "var(--warning)" },
  { tag: [tags.propertyName, tags.attributeName, tags.definition(tags.variableName)], color: "var(--info)" },
  { tag: [tags.typeName, tags.className, tags.tagName], color: "var(--magenta-text)" },
  { tag: [tags.heading], color: "var(--violet-text)", fontWeight: "700" },
  { tag: [tags.meta, tags.processingInstruction, tags.annotation], color: "var(--cyan)" },
  { tag: [tags.inserted], color: "var(--success)" },
  { tag: [tags.deleted, tags.invalid], color: "var(--danger)" },
  { tag: [tags.operator, tags.punctuation], color: "var(--text-muted)" },
]);

const theme = EditorView.theme({
  "&": { color: "var(--text)", backgroundColor: "var(--bg-0)", height: "100%", fontSize: "14px" },
  ".cm-content": { fontFamily: '"JetBrains Mono", ui-monospace, monospace', caretColor: "var(--cyan)" },
  ".cm-scroller": { fontFamily: '"JetBrains Mono", ui-monospace, monospace', lineHeight: "1.55" },
  ".cm-gutters": { backgroundColor: "var(--bg-1)", color: "var(--text-faint)", borderRight: "1px solid var(--border-subtle)" },
  ".cm-activeLine": { backgroundColor: "color-mix(in srgb, var(--bg-2) 55%, transparent)" },
  ".cm-activeLineGutter": { backgroundColor: "var(--bg-2)", color: "var(--text)" },
  "&.cm-focused .cm-selectionBackground, .cm-selectionBackground, .cm-content ::selection": {
    backgroundColor: "color-mix(in srgb, var(--violet-brand) 38%, transparent)",
  },
  ".cm-cursor, .cm-dropCursor": { borderLeftColor: "var(--cyan)", borderLeftWidth: "2px" },
  "&.cm-focused": { outline: "none" },
  ".cm-panels": { backgroundColor: "var(--bg-1)", color: "var(--text)", borderColor: "var(--border-subtle)" },
  ".cm-panels.cm-panels-top": { borderBottom: "1px solid var(--border-subtle)" },
  ".cm-textfield": {
    backgroundColor: "var(--bg-0)",
    color: "var(--text)",
    border: "1px solid var(--border-strong)",
    borderRadius: "6px",
    padding: "2px 6px",
  },
  ".cm-button": { backgroundImage: "none", backgroundColor: "var(--bg-2)", color: "var(--text)", border: "1px solid var(--border-strong)", borderRadius: "6px" },
  ".cm-searchMatch": { backgroundColor: "color-mix(in srgb, var(--warning) 30%, transparent)" },
  ".cm-searchMatch.cm-searchMatch-selected": { backgroundColor: "color-mix(in srgb, var(--cyan) 35%, transparent)" },
  ".cm-selectionMatch": { backgroundColor: "color-mix(in srgb, var(--info) 22%, transparent)" },
  ".cm-matchingBracket": { outline: "1px solid var(--cyan)", backgroundColor: "transparent" },
  ".cm-foldPlaceholder": { backgroundColor: "var(--bg-2)", color: "var(--text-muted)", border: "none" },
  ".cm-specialChar": { color: "var(--danger)" },
});

function styleNonce(): string | undefined {
  const v = document.querySelector<HTMLMetaElement>('meta[name="style-nonce"]')?.content;
  return v && !v.startsWith("__") ? v : undefined;
}

function indentFor(size: number): Extension {
  return [EditorState.tabSize.of(size || 4), indentUnit.of(size ? " ".repeat(size) : "\t")];
}

export const CodeEditor = forwardRef<CodeEditorHandle, Props>(function CodeEditor(props, ref) {
  const host = useRef<HTMLDivElement>(null);
  const view = useRef<EditorView | null>(null);
  const cb = useRef(props);
  const comps = useRef({ lang: new Compartment(), wrap: new Compartment(), indent: new Compartment(), ro: new Compartment() });

  useEffect(() => {
    cb.current = props;
  });

  useImperativeHandle(ref, () => ({
    getText: () => view.current?.state.doc.toString() ?? "",
    setText: (s: string) => {
      const v = view.current;
      if (v) v.dispatch({ changes: { from: 0, to: v.state.doc.length, insert: s } });
    },
    focus: () => view.current?.focus(),
  }));

  // Create once; later prop changes are applied through compartments.
  useEffect(() => {
    if (!host.current) return;
    const c = comps.current;
    const nonce = styleNonce();
    const v = new EditorView({
      parent: host.current,
      state: EditorState.create({
        doc: props.initial,
        extensions: [
          nonce ? EditorView.cspNonce.of(nonce) : [],
          lineNumbers(),
          foldGutter(),
          highlightActiveLineGutter(),
          highlightSpecialChars(),
          history(),
          drawSelection(),
          indentOnInput(),
          bracketMatching(),
          highlightActiveLine(),
          highlightSelectionMatches(),
          search({ top: true }),
          syntaxHighlighting(highlight),
          theme,
          keymap.of([
            {
              key: "Mod-s",
              preventDefault: true,
              run: () => {
                cb.current.onSave();
                return true;
              },
            },
            ...defaultKeymap,
            ...historyKeymap,
            ...searchKeymap,
            ...foldKeymap,
            indentWithTab,
          ]),
          c.lang.of([]),
          c.wrap.of(props.wrap ? EditorView.lineWrapping : []),
          c.indent.of(indentFor(props.tabSize)),
          c.ro.of([EditorState.readOnly.of(props.readOnly)]),
          EditorView.contentAttributes.of({ "aria-label": props.label }),
          EditorView.updateListener.of((u) => {
            if (u.docChanged) cb.current.onDirty();
            if (u.selectionSet || u.docChanged) {
              const pos = u.state.selection.main.head;
              const line = u.state.doc.lineAt(pos);
              cb.current.onCursor(line.number, pos - line.from + 1);
            }
          }),
        ],
      }),
    });
    view.current = v;
    let alive = true;
    void languageFor(props.path).then((l) => {
      if (alive && l) v.dispatch({ effects: c.lang.reconfigure(l) });
    });
    return () => {
      alive = false;
      v.destroy();
      view.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    view.current?.dispatch({ effects: comps.current.wrap.reconfigure(props.wrap ? EditorView.lineWrapping : []) });
  }, [props.wrap]);
  useEffect(() => {
    view.current?.dispatch({ effects: comps.current.indent.reconfigure(indentFor(props.tabSize)) });
  }, [props.tabSize]);
  useEffect(() => {
    view.current?.dispatch({ effects: comps.current.ro.reconfigure([EditorState.readOnly.of(props.readOnly)]) });
  }, [props.readOnly]);

  return <div ref={host} className="editor-host h-full min-h-[320px]" />;
});
