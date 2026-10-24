import js from "@eslint/js";
import tseslint from "typescript-eslint";
import reactHooks from "eslint-plugin-react-hooks";

export default tseslint.config(
  { ignores: ["dist", "node_modules"] },
  js.configs.recommended,
  {
    files: ["scripts/**/*.mjs"],
    languageOptions: { globals: { console: "readonly", process: "readonly", URL: "readonly" } },
  },
  ...tseslint.configs.strict,
  {
    plugins: { "react-hooks": reactHooks },
    rules: {
      ...reactHooks.configs.recommended.rules,
      // SPEC §3.5: all system data is rendered as text; raw HTML injection is forbidden.
      "no-restricted-syntax": [
        "error",
        { selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']", message: "dangerouslySetInnerHTML is forbidden (SPEC §3.5)." },
        { selector: "MemberExpression[property.name=/^(innerHTML|outerHTML)$/]", message: "innerHTML/outerHTML are forbidden (SPEC §3.5)." },
        { selector: "CallExpression[callee.property.name='insertAdjacentHTML']", message: "insertAdjacentHTML is forbidden." },
      ],
      "no-eval": "error",
      "no-implied-eval": "error",
      "no-new-func": "error",
    },
  },
);
