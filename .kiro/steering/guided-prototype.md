---
inclusion: auto
name: guided-prototype
description: Instruction to create guided prototypes as static sites when user asks for to create POCs. Use when creating frontends or html proof-of-concepts.
---

# Brainstorming & Idea Validation

This workspace is used for a brainstorming and idea validation hackathon. The goal is to rapidly explore ideas, validate concepts, and build lightweight prototypes that communicate the vision clearly.

### Requirements Phase — Ask Before You Assume

When creating requirements for a spec, you MUST ask the user clarifying questions before finalizing. Do not generate a full requirements list from a vague prompt. Instead:

1. If the user has provided a requirement, start by acknowledging the idea and summarizing your understanding in one or two sentences. Otherwise, ask the user to describe they would like to build.
2. **Always ask the user for a project name** before doing anything else. This name will be used to create the project folder. If the user doesn't provide one, suggest a short, descriptive kebab-case name (e.g., `car-compare`, `credit-cards`) and confirm before proceeding.
3. Ask at least 3 targeted clarifying questions to better understand. Here are some examples you may consider using, or you may also ask your own questions.
   - Who is the target user or audience?
   - What is the core problem being solved or value being delivered?
   - What is the single most important interaction or flow to demonstrate?
   - Are there any existing products or references to draw inspiration from?
   - What should the prototype prioritize: visual polish, interaction flow, or data storytelling?
4. Do not ask more than 5 questions.
5. Always provide multiple suggestions for your question, with the last one being "Others, describe your answer".
6. Always only ask one question at a time, and wait for user to answer before proceeding.
7. Ask the user if there is anything else they would like to add for the requirements before proceeding. This one is free text so you do not need to provide options.
8. Keep requirements focused on what the prototype needs to communicate, not production concerns.
9. Once requirements are finalized, document them in `<project_name>/requirements.md`. This serves as the single source of truth for the idea.
10. Use mock data when necessary to simulate backend.
11. Always try to include the full scope of the requirements to build a visually functional and interactive app.
12. Once the requirements are documented, you may begin building the static site using the guidelines below.

# Static Site Only — Development Rules

All frontend application development in this project must produce static sites that run entirely in the browser with no server-side runtime.

## Technology Constraints

- Use only plain HTML, CSS, and JavaScript (vanilla JS).
- Do not introduce dependencies on Node.js, Python, or any other server-side runtime.
- Do not use npm, pip, or any package manager. No `node_modules`, no `package.json`.
- Do not use build tools, bundlers, or transpilers (e.g., Webpack, Vite, Babel, TypeScript).
- Do not use frontend frameworks that require a build step (e.g., React, Vue, Angular, Svelte).
- Use DaisyUI and/or Tailwind CSS for any components
- Use Lucide for icons
- Use Chart.js for charts and visuals

## Architecture

- Applications must be fully client-side. All logic runs in the browser.
- Files should be servable by opening `index.html` directly in a browser or via a simple static file server.
- Prefer a flat file structure: `index.html`, `style.css`, `app.js` (or similar minimal layout).
- Use ES modules (`<script type="module">`) when modularization is needed.
- Mock API requests/response if necessary.

## External Resources

- CDN-hosted libraries (e.g., a charting library loaded via `<script>` tag) are acceptable when they add clear value and require no build step.
- Always load external scripts from versioned, pinned URLs to ensure reproducibility.

## Code Style

- Write clean, readable, well-commented code.
- Use semantic HTML elements for structure and accessibility.
- Keep CSS in dedicated `.css` files rather than inline styles.
- Keep JavaScript in dedicated `.js` files rather than inline scripts.

## Gotchas

The following are things that can go wrong and you are to handle them up front:

CORS errors: type="module" enforces strict CORS checks, and opening the file directly (via file://) or with some simple servers can trigger that. Since we're not using any ES module imports, a regular <script> tag does the job just fine.