import typescriptEslint from "@typescript-eslint/eslint-plugin";
import typescriptParser from "@typescript-eslint/parser";
import js from "@eslint/js";
import globals from "globals";

export default [
  {
    ignores: ["**/node_modules/**", "**/dist/**", "results/**"]
  },
  js.configs.recommended,

  {
    files: ["**/*.ts", "**/*.tsx"],
    languageOptions: {
      parser: typescriptParser,
      globals: {
        node: true,
        ...globals.node,    
        ...globals.browser, 
        Bun: "readonly",     
      },
    },
    plugins: {
      "@typescript-eslint": typescriptEslint,
    },
    rules: {
      "semi": ["error", "always"],
      "quotes": ["error", "double"],
      "@typescript-eslint/no-unused-vars": "warn",
    },
  },
];
