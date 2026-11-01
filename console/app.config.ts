// Nuxt UI semantic colors. The actual shades are overridden in
// app/assets/css/main.css with the mockup tokens (--pri, --ok, --ko, --warn, --obs).
export default defineAppConfig({
  ui: {
    colors: {
      primary: 'sky',
      secondary: 'violet',
      success: 'emerald',
      info: 'violet',
      warning: 'amber',
      error: 'red',
      neutral: 'slate',
    },
  },
})
