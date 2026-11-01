// https://eslint.nuxt.com
import withNuxt from './.nuxt/eslint.config.mjs'

export default withNuxt({
  rules: {
    // `const { a: _a, ...rest } = v` drops fields of an API view (rest siblings are intentional).
    '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_', ignoreRestSiblings: true }],
    'vue/multi-word-component-names': 'off',
    'vue/no-v-html': 'error',
  },
})
