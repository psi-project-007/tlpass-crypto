import { defineConfig } from 'eslint/config';  
import js from '@eslint/js';                   
import tseslint from 'typescript-eslint';      

export default defineConfig(
  { ignores: ['dist', 'coverage'] },           
  js.configs.recommended,                      
  tseslint.configs.strict,                     
);