import { mount } from 'svelte';
import './styles.css';
import App from './App.svelte';
import { applyTheme, initialTheme } from './lib/theme';

applyTheme(initialTheme());

const target = document.getElementById('app');
if (!target) throw new Error('missing #app');
export default mount(App, { target });
