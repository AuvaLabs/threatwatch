import { render } from "preact";
import { App } from "./App";
import "./styles/tokens.css";
import "./styles/base.css";
import "./styles/shell.css";
import "./styles/components.css";
import "./styles/views.css";
import "./styles/operations.css";
import "./styles/responsive.css";

const root = document.getElementById("app");
if (!root) throw new Error("ThreatWatch application root is missing");
render(<App />, root);
