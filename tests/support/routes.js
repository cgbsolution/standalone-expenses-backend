// Every route the app registers, with its full path.
//
// Express 5 keeps no mount path once a router is mounted, so the paths are
// recorded as the app is built: Router.prototype.route (each GET/POST/…) and
// Router.prototype.use (each router mounted under a prefix) are wrapped before
// app.js is loaded. Call loadAppWithRoutes() before anything requires app.js.

const express = require("express");

function loadAppWithRoutes() {
  const Router = express.Router;
  const routes = []; // { router, path, route }
  const mounts = new Map(); // child router -> { parent, path }

  const originalRoute = Router.prototype.route;
  const originalUse = Router.prototype.use;
  Router.prototype.route = function route(path) {
    const created = originalRoute.call(this, path);
    routes.push({ router: this, path, route: created });
    return created;
  };
  Router.prototype.use = function use(...args) {
    const path = typeof args[0] === "string" ? args[0] : "/";
    for (const fn of args.flat()) {
      if (fn instanceof Router) mounts.set(fn, { parent: this, path });
    }
    return originalUse.apply(this, args);
  };

  let app;
  try {
    ({ app } = require("../../app"));
  } finally {
    Router.prototype.route = originalRoute;
    Router.prototype.use = originalUse;
  }

  const prefixOf = (router) => {
    let prefix = "";
    for (let at = mounts.get(router); at; at = mounts.get(at.parent)) {
      prefix = (at.path === "/" ? "" : at.path) + prefix;
    }
    return prefix;
  };

  const list = [];
  for (const { router, path, route } of routes) {
    for (const method of Object.keys(route.methods)) {
      if (method === "_all") continue;
      list.push({ method: method.toUpperCase(), path: prefixOf(router) + path });
    }
  }
  return { app, routes: list };
}

/** A concrete URL for a route pattern: every :param becomes "x". */
function concrete(path) {
  return path.replace(/:[A-Za-z_]\w*/g, "x");
}

module.exports = { loadAppWithRoutes, concrete };
