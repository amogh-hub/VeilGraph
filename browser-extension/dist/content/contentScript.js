"use strict";
(() => {
  // src/content/actionSecurity.ts
  var ROLE_COMPATIBILITY = {
    CLICK: /* @__PURE__ */ new Set(["button", "link", "menuitem", "checkbox", "radio", "option"]),
    TYPE: /* @__PURE__ */ new Set(["textbox", "combobox"]),
    SELECT: /* @__PURE__ */ new Set(["combobox", "checkbox", "radio", "option", "menuitem"])
  };
  function assertLiveElementSecurity(action, snapshot) {
    if (!snapshot.connected) throw new Error("target DOM node is no longer connected");
    if (!snapshot.visible) throw new Error("target is not visibly present in the viewport");
    const mutating = action.action !== "READ";
    if (mutating && snapshot.occluded) throw new Error("target is visually occluded");
    if (mutating && snapshot.pointerEventsNone) throw new Error("target cannot receive pointer interaction");
    if (mutating && (snapshot.disabled || snapshot.ariaDisabled)) throw new Error("target is disabled");
    const allowed = ROLE_COMPATIBILITY[action.action];
    if (allowed && !allowed.has(snapshot.role.toLowerCase())) {
      throw new Error(`${action.action} is incompatible with live target role ${snapshot.role}`);
    }
    if (action.action === "TYPE") {
      if (snapshot.credentialLike || snapshot.inputType === "password" || snapshot.inputType === "file") {
        throw new Error("server-generated typing into credential/file fields is forbidden");
      }
      const typeable = snapshot.tag === "input" || snapshot.tag === "textarea" || snapshot.role.toLowerCase() === "textbox";
      if (!typeable) throw new Error("live target is not locally typeable");
    }
    if (action.action === "SELECT") {
      const selectable = snapshot.tag === "select" || snapshot.inputType === "checkbox" || snapshot.inputType === "radio";
      if (!selectable) throw new Error("live target is not a supported local selection control");
    }
  }

  // src/perception/geometry.ts
  function clampBp(value) {
    return Math.max(0, Math.min(1e4, Math.round(value)));
  }
  function clipRectToViewport(rect, viewportWidth, viewportHeight) {
    const width = Math.max(1, viewportWidth);
    const height = Math.max(1, viewportHeight);
    const left = Math.max(0, Math.min(width, rect.left));
    const top = Math.max(0, Math.min(height, rect.top));
    const right = Math.max(0, Math.min(width, rect.right));
    const bottom = Math.max(0, Math.min(height, rect.bottom));
    if (right <= left || bottom <= top) return null;
    return [
      clampBp(left / width * 1e4),
      clampBp(top / height * 1e4),
      clampBp(right / width * 1e4),
      clampBp(bottom / height * 1e4)
    ];
  }

  // src/content/domCapture.ts
  var MAX_CAPTURED_ELEMENTS = 2e3;
  var ids = /* @__PURE__ */ new WeakMap();
  var elementsById = /* @__PURE__ */ new Map();
  function nowMs() {
    return typeof performance !== "undefined" ? performance.now() : Date.now();
  }
  function localId(element) {
    const existing = ids.get(element);
    if (existing) {
      elementsById.set(existing, element);
      return existing;
    }
    const bytes = crypto.getRandomValues(new Uint8Array(12));
    const token = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
    const created = `vg_${token}`;
    ids.set(element, created);
    elementsById.set(created, element);
    return created;
  }
  function resolveLocalElement(localIdValue) {
    const element = elementsById.get(localIdValue);
    if (!element || !element.isConnected || ids.get(element) !== localIdValue) {
      elementsById.delete(localIdValue);
      return null;
    }
    return element;
  }
  function viewportSize() {
    return {
      width: Math.max(document.documentElement.clientWidth, window.innerWidth || 0, 1),
      height: Math.max(document.documentElement.clientHeight, window.innerHeight || 0, 1)
    };
  }
  function normalizedBox(element) {
    const { width, height } = viewportSize();
    const rect = element.getBoundingClientRect();
    return clipRectToViewport(
      { left: rect.left, top: rect.top, right: rect.right, bottom: rect.bottom },
      width,
      height
    );
  }
  function isVisibleInViewport(element) {
    const style = getComputedStyle(element);
    if (style.display === "none" || style.visibility === "hidden" || Number(style.opacity || "1") <= 0) return false;
    return normalizedBox(element) !== null;
  }
  function labelledBy(element) {
    const idsValue = element.getAttribute("aria-labelledby")?.trim();
    if (!idsValue) return "";
    return idsValue.split(/\s+/).map((id) => document.getElementById(id)?.textContent?.trim() ?? "").filter(Boolean).join(" ");
  }
  function associatedLabel(element) {
    if (!(element instanceof HTMLInputElement || element instanceof HTMLTextAreaElement || element instanceof HTMLSelectElement)) return "";
    return Array.from(element.labels ?? []).map((label) => label.textContent?.trim() ?? "").filter(Boolean).join(" ");
  }
  function accessibleName(element) {
    const candidates = [
      element.getAttribute("aria-label")?.trim() ?? "",
      labelledBy(element),
      associatedLabel(element),
      element.getAttribute("title")?.trim() ?? "",
      element instanceof HTMLInputElement ? element.placeholder.trim() : "",
      element.textContent?.trim() ?? ""
    ];
    return candidates.find(Boolean)?.slice(0, 512) ?? "";
  }
  function implicitRole(element) {
    const explicit = element.getAttribute("role")?.trim();
    if (explicit) return explicit;
    const tag = element.tagName.toLowerCase();
    if (tag === "button") return "button";
    if (tag === "a" && element.hasAttribute("href")) return "link";
    if (tag === "textarea") return "textbox";
    if (tag === "select") return "combobox";
    if (tag === "input") {
      const input = element;
      if (input.type === "checkbox") return "checkbox";
      if (input.type === "radio") return "radio";
      if (input.type === "button" || input.type === "submit" || input.type === "reset") return "button";
      return "textbox";
    }
    if (/^h[1-6]$/.test(tag)) return "heading";
    return tag;
  }
  function privacyHints(element) {
    const hints = [];
    const tokens = [
      element.getAttribute("name"),
      element.getAttribute("id"),
      element.getAttribute("autocomplete"),
      element.getAttribute("aria-label"),
      element.getAttribute("placeholder"),
      element instanceof HTMLInputElement ? element.type : null
    ].filter((value) => Boolean(value)).join(" ").toLowerCase();
    const classes = [
      [/pass(word|code)?|pin|otp|cvv|secret/, "credential"],
      [/email|e-mail/, "email"],
      [/phone|mobile|tel/, "phone"],
      [/name|given-name|family-name/, "person_name"],
      [/aadhaar|aadhar|pan|passport|license|licence|national.?id/, "government_identifier"],
      [/address|postcode|postal|zip|city|locality/, "location"],
      [/card|account|iban|ifsc|upi|bank/, "financial"],
      [/dob|birth|age/, "quasi_identifier"],
      [/patient|medical|health|diagnos/, "health"]
    ];
    for (const [pattern, label] of classes) if (pattern.test(tokens)) hints.push(label);
    return hints;
  }
  function shouldCapture(element) {
    if (!isVisibleInViewport(element)) return false;
    const tag = element.tagName.toLowerCase();
    if (["script", "style", "noscript", "svg", "path", "meta", "link"].includes(tag)) return false;
    if (element.matches('button,a[href],input,textarea,select,[role],[contenteditable="true"],h1,h2,h3,h4,h5,h6,label')) return true;
    const text = element.textContent?.trim() ?? "";
    return text.length > 0 && text.length <= 512 && element.children.length === 0;
  }
  function collectRoots() {
    const roots = [document];
    const visit = (root) => {
      for (const element of Array.from(root.querySelectorAll("*"))) {
        if (element.shadowRoot) {
          roots.push(element.shadowRoot);
          visit(element.shadowRoot);
        }
      }
    };
    visit(document);
    return roots;
  }
  function captureFrame() {
    const started = nowMs();
    for (const [localIdValue, element] of elementsById) {
      if (!element.isConnected) elementsById.delete(localIdValue);
    }
    const roots = collectRoots();
    const candidates = [];
    for (const root of roots) candidates.push(...Array.from(root.querySelectorAll("*")).filter(shouldCapture));
    const eligible = Array.from(new Set(candidates));
    const unique = eligible.slice(0, MAX_CAPTURED_ELEMENTS);
    const elements = [];
    for (const element of unique) {
      const bbox = normalizedBox(element);
      if (!bbox) continue;
      const input = element instanceof HTMLInputElement ? element : null;
      const textarea = element instanceof HTMLTextAreaElement ? element : null;
      const select = element instanceof HTMLSelectElement ? element : null;
      const rawValue = input?.value ?? textarea?.value ?? select?.value;
      elements.push({
        localId: localId(element),
        tag: element.tagName.toLowerCase(),
        role: implicitRole(element),
        accessibleName: accessibleName(element),
        visibleText: (element.textContent?.trim() ?? "").slice(0, 512),
        ...input ? { inputType: input.type } : {},
        ...rawValue ? { rawValue: rawValue.slice(0, 2048) } : {},
        disabled: element instanceof HTMLButtonElement || element instanceof HTMLInputElement || element instanceof HTMLTextAreaElement || element instanceof HTMLSelectElement ? element.disabled : false,
        ...input?.type === "checkbox" || input?.type === "radio" ? { checked: input.checked } : {},
        ...element instanceof HTMLOptionElement ? { selected: element.selected } : {},
        bbox,
        privacyHints: privacyHints(element)
      });
    }
    let inaccessibleDescendantFrames = 0;
    for (const frame of Array.from(document.querySelectorAll("iframe"))) {
      try {
        void frame.contentDocument?.documentElement;
      } catch {
        inaccessibleDescendantFrames += 1;
      }
    }
    const { width: viewportWidth, height: viewportHeight } = viewportSize();
    const documentElement = document.documentElement;
    return {
      frameId: -1,
      isTopFrame: window.top === window,
      origin: location.origin,
      href: location.href,
      title: document.title.slice(0, 512),
      viewportWidth,
      viewportHeight,
      devicePixelRatioBasisPoints: Math.max(1e3, Math.min(8e4, Math.round((window.devicePixelRatio || 1) * 1e4))),
      scrollX: Math.round(window.scrollX),
      scrollY: Math.round(window.scrollY),
      documentWidth: Math.max(documentElement.scrollWidth, documentElement.clientWidth, 1),
      documentHeight: Math.max(documentElement.scrollHeight, documentElement.clientHeight, 1),
      elements,
      eligibleElementCount: eligible.length,
      capturedElementCount: elements.length,
      captureTruncated: eligible.length > MAX_CAPTURED_ELEMENTS,
      shadowRootCount: Math.max(0, roots.length - 1),
      captureElapsedMs: Math.max(0, Math.round(nowMs() - started)),
      inaccessibleDescendantFrames
    };
  }

  // src/content/actionExecutor.ts
  function isVisible(element) {
    const style = getComputedStyle(element);
    if (style.display === "none" || style.visibility === "hidden" || Number(style.opacity || "1") <= 0) return false;
    const rect = element.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0 && rect.right > 0 && rect.bottom > 0 && rect.left < window.innerWidth && rect.top < window.innerHeight;
  }
  function isOccluded(element) {
    const rect = element.getBoundingClientRect();
    const x = Math.max(0, Math.min(window.innerWidth - 1, rect.left + rect.width / 2));
    const y = Math.max(0, Math.min(window.innerHeight - 1, rect.top + rect.height / 2));
    const topmost = document.elementFromPoint(x, y);
    if (!topmost) return true;
    return !(element === topmost || element.contains(topmost) || topmost.contains(element));
  }
  function liveSnapshot(element) {
    const style = getComputedStyle(element);
    const input = element instanceof HTMLInputElement ? element : null;
    const control = element instanceof HTMLButtonElement || element instanceof HTMLInputElement || element instanceof HTMLTextAreaElement || element instanceof HTMLSelectElement ? element : null;
    const hints = privacyHints(element);
    return {
      connected: element.isConnected,
      visible: isVisible(element),
      occluded: isOccluded(element),
      disabled: control?.disabled ?? false,
      ariaDisabled: element.getAttribute("aria-disabled")?.toLowerCase() === "true",
      pointerEventsNone: style.pointerEvents === "none",
      role: implicitRole(element),
      tag: element.tagName.toLowerCase(),
      inputType: input?.type ?? null,
      credentialLike: hints.includes("credential")
    };
  }
  function dispatchValueEvents(element) {
    element.dispatchEvent(new Event("input", { bubbles: true, composed: true }));
    element.dispatchEvent(new Event("change", { bubbles: true, composed: true }));
  }
  function executeType(element, value) {
    if (element instanceof HTMLInputElement || element instanceof HTMLTextAreaElement) {
      element.focus({ preventScroll: true });
      element.value = value;
      dispatchValueEvents(element);
      return;
    }
    if (element instanceof HTMLElement && element.isContentEditable) {
      element.focus({ preventScroll: true });
      element.textContent = value;
      dispatchValueEvents(element);
      return;
    }
    throw new Error("live target is not locally typeable");
  }
  function parseBooleanSelection(value) {
    const normalized = value.trim().toLowerCase();
    if (["true", "on", "yes", "checked", "1"].includes(normalized)) return true;
    if (["false", "off", "no", "unchecked", "0"].includes(normalized)) return false;
    return null;
  }
  function executeSelect(element, value) {
    if (element instanceof HTMLSelectElement) {
      const normalized = value.trim().toLowerCase();
      const option = Array.from(element.options).find((candidate) => candidate.value === value || candidate.text.trim().toLowerCase() === normalized);
      if (!option) throw new Error("requested select option is not present in the live control");
      element.value = option.value;
      dispatchValueEvents(element);
      return;
    }
    if (element instanceof HTMLInputElement && (element.type === "checkbox" || element.type === "radio")) {
      const desired = parseBooleanSelection(value);
      if (desired === null) throw new Error("checkbox/radio selection value must be a boolean-like value");
      if (element.type === "radio" && desired === false) {
        if (element.checked) {
          element.checked = false;
          dispatchValueEvents(element);
        }
        return;
      }
      if (element.checked !== desired) element.click();
      return;
    }
    throw new Error("live target is not a supported local selection control");
  }
  function executeFrameAction(executionId, action) {
    if (action.action === "SCROLL") {
      const delta = action.scroll_delta_y;
      if (!delta) throw new Error("SCROLL action is missing delta");
      window.scrollBy({ top: delta, left: 0, behavior: "auto" });
      return { executionId, action: action.action, targetId: null };
    }
    if (action.action === "NAVIGATE" || action.action === "WAIT") {
      throw new Error(`${action.action} must be executed by the trusted service worker`);
    }
    if (!action.target_id) throw new Error(`${action.action} requires a local target`);
    const element = resolveLocalElement(action.target_id);
    if (!element) throw new Error("target DOM node is stale or no longer available");
    assertLiveElementSecurity(action, liveSnapshot(element));
    if (action.action === "CLICK") {
      if (!(element instanceof HTMLElement)) throw new Error("CLICK target is not an HTMLElement");
      element.focus({ preventScroll: true });
      element.click();
    } else if (action.action === "TYPE") {
      if (action.value === null || action.value === void 0) throw new Error("TYPE action is missing value");
      executeType(element, action.value);
    } else if (action.action === "SELECT") {
      if (action.value === null || action.value === void 0) throw new Error("SELECT action is missing value");
      executeSelect(element, action.value);
    } else if (action.action === "READ") {
    }
    return { executionId, action: action.action, targetId: action.target_id };
  }

  // src/content/contentScript.ts
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    const request = message;
    if (request.type === "VG_CAPTURE_FRAME") {
      try {
        sendResponse({ ok: true, data: captureFrame() });
      } catch (error) {
        sendResponse({ ok: false, error: error instanceof Error ? error.message : "frame capture failed" });
      }
      return;
    }
    if (request.type === "VG_EXECUTE_FRAME_ACTION" && typeof request.executionId === "string" && request.executionId.startsWith("VGX-") && request.action) {
      if (sender.id !== chrome.runtime.id || sender.tab) {
        sendResponse({ ok: false, error: "untrusted action-execution sender" });
        return;
      }
      try {
        const result = executeFrameAction(request.executionId, request.action);
        sendResponse({ ok: true, data: result });
      } catch (error) {
        sendResponse({ ok: false, error: error instanceof Error ? error.message : "local frame action blocked" });
      }
    }
  });
})();
