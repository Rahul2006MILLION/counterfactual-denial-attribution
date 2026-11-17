import "./styles/base.css";
import "./styles/sections.css";
import {
  initCardGlow,
  initCursor,
  initFlow,
  initHeroParallax,
  initMagnetic,
  initNav,
  initReveal,
  initStack,
} from "./fx/interactions";
import { initDemo } from "./sections/demo";
import { initAgent, initModes } from "./sections/agent";

const root = document.documentElement;
const ready = () => root.classList.add("is-ready");

initNav();
initReveal();
initFlow();
initStack();
initCardGlow();
initHeroParallax();
initCursor();
initMagnetic();
initDemo();
initModes();
initAgent();

// Load the WebGL hero as its own chunk so the page is interactive immediately.
const canvas = document.querySelector<HTMLCanvasElement>("[data-hero-canvas]");
const hero = document.querySelector<HTMLElement>("[data-hero]");
if (canvas && hero) {
  import("./scene/hero")
    .then(({ initHero }) => initHero(canvas, hero, ready))
    .catch(() => {
      root.classList.add("no-webgl");
      ready();
    });
} else {
  ready();
}
// Never leave the hero text hidden if anything above is slow.
window.setTimeout(ready, 2500);
