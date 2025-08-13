module.exports = {
  root: true,
  env: { browser: true, es2020: true },
  extends: [
    'eslint:recommended',
  ],
  ignorePatterns: ['dist', '.eslintrc.cjs'],
  parser: '@typescript-eslint/parser',
  plugins: ['@typescript-eslint', 'react', 'react-hooks', 'react-refresh'],
  rules: {
    'react-refresh/only-export-components': [
      'warn',
      { allowConstantExport: true },
    ],
    '@typescript-eslint/no-unused-vars': ['error', { 
      argsIgnorePattern: '^_',
      varsIgnorePattern: '^_',
      ignoreRestSiblings: true 
    }],
    '@typescript-eslint/no-explicit-any': 'warn',
    '@typescript-eslint/no-redeclare': 'error',
    '@typescript-eslint/no-undef': 'error',
    'prefer-const': 'error',
    'no-var': 'error',
    'no-redeclare': 'off', // Отключаем базовое правило в пользу TypeScript версии
    'no-undef': 'off', // Отключаем базовое правило в пользу TypeScript версии
    'react/react-in-jsx-scope': 'off', // Не нужно в React 17+
    'react/prop-types': 'off', // Используем TypeScript
  },
  settings: {
    react: {
      version: 'detect',
    },
  },
} 