// Components downloaded: chips,copy,form,input,notifications,popup,spinner,theme-toggle
const smChips = document.createElement("template");
(smChips.innerHTML =
  '<style> *{ padding: 0; margin: 0; -webkit-box-sizing: border-box; box-sizing: border-box; }  :host{ padding: 1rem 0; max-width: 100%; } .hide{ opacity: 0; pointer-events: none; } input[type="radio"]{ display: none; } .scrolling-container{ position: relative; display: grid; grid-template-columns: min-content minmax(0,1fr) min-content; grid-template-rows: 1fr; } .sm-chips{ display: flex; position: relative; grid-area: 1/1/2/-1; gap: var(--gap, 0.5rem); overflow: auto hidden; } :host([multiline]) .sm-chips{ flex-wrap: wrap; } :host(:not([multiline])) .sm-chips{ max-width: 100%;  align-items: center; } .nav-button{ display: flex; z-index: 2; border: none; padding: 0.3rem; cursor: pointer; align-items: center; background: rgba(var(--background-color,(255,255,255)), 1); grid-row: 1; transition: opacity 0.2s; } .nav-button--left{ grid-column: 1; justify-self: start; } .nav-button--right{ grid-column: 3; justify-self: end; } .cover{ position: absolute; z-index: 1; width: 5rem; height: 100%; pointer-events: none; grid-row: 1; transition: opacity 0.2s; } .cover--left{ grid-column: 1; } .cover--right{ grid-column: 3; } .nav-button--right::before{ background-color: red; } .icon{ height: 1.2rem; width: 1.2rem; fill: rgba(var(--text-color,(17,17,17)), .8); } @media (hover: none){ ::-webkit-scrollbar { height: 0; } .nav-button{ display: none; } .sm-chips{ overflow: auto hidden; } .cover{ width: 2rem; } .cover--left{ background: linear-gradient(90deg, rgba(var(--background-color,(255,255,255)), 1), transparent); } .cover--right{ right: 0; background: linear-gradient(90deg, transparent, rgba(var(--background-color,(255,255,255)), 1)); } } @media (hover: hover){ ::-webkit-scrollbar-track { background-color: transparent !important; } ::-webkit-scrollbar { height: 0; background-color: transparent; } .sm-chips{ overflow: hidden; } .cover--left{ background: linear-gradient(90deg, rgba(var(--background-color,(255,255,255)), 1) 60%, transparent); } .cover--right{ right: 0; background: linear-gradient(90deg, transparent 0%, rgba(var(--background-color,(255,255,255)), 1) 40%); } }</style><section class="scrolling-container"> <div class="cover cover--left hide"></div> <button class="nav-button nav-button--left hide"> <svg class="icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="24" height="24"><path fill="none" d="M0 0h24v24H0z"/><path d="M10.828 12l4.95 4.95-1.414 1.414L8 12l6.364-6.364 1.414 1.414z"/></svg> </button> <section class="sm-chips" part="chips-wrapper"> <slot></slot> </section> <button class="nav-button nav-button--right hide"> <svg class="icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="24" height="24"><path fill="none" d="M0 0h24v24H0z"/><path d="M13.172 12l-4.95-4.95 1.414-1.414L16 12l-6.364 6.364-1.414-1.414z"/></svg> </button> <div class="cover cover--right hide"></div></section>'),
  customElements.define(
    "sm-chips",
    class extends HTMLElement {
      constructor() {
        super(),
          this.attachShadow({ mode: "open" }).append(
            smChips.content.cloneNode(!0)
          ),
          (this.chipsWrapper = this.shadowRoot.querySelector(".sm-chips")),
          (this.coverLeft = this.shadowRoot.querySelector(".cover--left")),
          (this.coverRight = this.shadowRoot.querySelector(".cover--right")),
          (this.navButtonLeft =
            this.shadowRoot.querySelector(".nav-button--left")),
          (this.navButtonRight =
            this.shadowRoot.querySelector(".nav-button--right")),
          (this.slottedOptions = void 0),
          (this._value = void 0),
          (this.scrollDistance = 0),
          (this.assignedElements = []),
          (this.scrollLeft = this.scrollLeft.bind(this)),
          (this.scrollRight = this.scrollRight.bind(this)),
          (this.fireEvent = this.fireEvent.bind(this)),
          (this.setSelectedOption = this.setSelectedOption.bind(this));
      }
      get value() {
        return this._value;
      }
      set value(t) {
        this.setSelectedOption(t);
      }
      scrollLeft() {
        this.chipsWrapper.scrollBy({
          left: -this.scrollDistance,
          behavior: "smooth",
        });
      }
      scrollRight() {
        this.chipsWrapper.scrollBy({
          left: this.scrollDistance,
          behavior: "smooth",
        });
      }
      setSelectedOption(t) {
        this._value !== t &&
          ((this._value = t),
          this.assignedElements.forEach((e) => {
            e.value == t
              ? (e.setAttribute("selected", ""),
                e.scrollIntoView({
                  behavior: "smooth",
                  block: "nearest",
                  inline: "center",
                }))
              : e.removeAttribute("selected");
          }));
      }
      fireEvent() {
        this.dispatchEvent(
          new CustomEvent("change", {
            bubbles: !0,
            composed: !0,
            detail: { value: this._value },
          })
        );
      }
      connectedCallback() {
        this.setAttribute("role", "listbox");
        const t = this.shadowRoot.querySelector("slot");
        t.addEventListener("slotchange", (e) => {
          n.disconnect(),
            i.disconnect(),
            this.observeSelf.disconnect(),
            clearTimeout(this.slotChangeTimeout),
            (this.slotChangeTimeout = setTimeout(() => {
              (this.assignedElements = t.assignedElements()),
                this.assignedElements.forEach((t) => {
                  t.hasAttribute("selected") && (this._value = t.value);
                }),
                this.observeSelf.observe(this);
            }, 0));
        });
        const e = new ResizeObserver((t) => {
          t.forEach((t) => {
            if (t.contentBoxSize) {
              const e = Array.isArray(t.contentBoxSize)
                ? t.contentBoxSize[0]
                : t.contentBoxSize;
              this.scrollDistance = 0.6 * e.inlineSize;
            } else this.scrollDistance = 0.6 * t.contentRect.width;
          });
        });
        e.observe(this),
          (this.observeSelf = new IntersectionObserver(
            (t, e) => {
              t.forEach((t) => {
                t.isIntersecting &&
                  !this.hasAttribute("multiline") &&
                  this.assignedElements.length > 0 &&
                  (n.observe(this.assignedElements[0]),
                  i.observe(
                    this.assignedElements[this.assignedElements.length - 1]
                  ),
                  e.unobserve(this));
              });
            },
            { threshold: 1 }
          )),
          this.chipsWrapper.addEventListener("option-clicked", (t) => {
            this._value !== t.target.value &&
              (this.setSelectedOption(t.target.value), this.fireEvent());
          });
        const n = new IntersectionObserver(
            (t) => {
              t.forEach((t) => {
                t.isIntersecting
                  ? (this.navButtonLeft.classList.add("hide"),
                    this.coverLeft.classList.add("hide"))
                  : (this.navButtonLeft.classList.remove("hide"),
                    this.coverLeft.classList.remove("hide"));
              });
            },
            { threshold: 1, root: this }
          ),
          i = new IntersectionObserver(
            (t) => {
              t.forEach((t) => {
                t.isIntersecting
                  ? (this.navButtonRight.classList.add("hide"),
                    this.coverRight.classList.add("hide"))
                  : (this.navButtonRight.classList.remove("hide"),
                    this.coverRight.classList.remove("hide"));
              });
            },
            { threshold: 1, root: this }
          );
        this.navButtonLeft.addEventListener("click", this.scrollLeft),
          this.navButtonRight.addEventListener("click", this.scrollRight);
      }
      disconnectedCallback() {
        this.navButtonLeft.removeEventListener("click", this.scrollLeft),
          this.navButtonRight.removeEventListener("click", this.scrollRight);
      }
    }
  );
const smChip = document.createElement("template");
(smChip.innerHTML =
  '<style> *{ padding: 0; margin: 0; -webkit-box-sizing: border-box; box-sizing: border-box; }  :host(:focus-within){ outline: none; } :host(:focus-within) .sm-chip{ box-shadow: 0 0 0 0.1rem var(--accent-color,teal) inset; } :host(:hover:not([selected])) .sm-chip{ background-color: rgba(var(--text-color,(17,17,17)), 0.06); } .sm-chip{ display: flex; flex-shrink: 0; cursor: pointer; white-space: nowrap; padding: var(--padding, 0.5rem 0.8rem); transition: background 0.3s; border-radius: var(--border-radius, 0.5rem); -webkit-tap-highlight-color: transparent; background: var(--background,inherit); } :host([selected]) .sm-chip{ background-color: var(--accent-color, teal); color: rgba(var(--background-color, (255,255,255)), 1); }</style><span class="sm-chip" part="chip"> <slot></slot></span>'),
  customElements.define(
    "sm-chip",
    class extends HTMLElement {
      constructor() {
        super(),
          this.attachShadow({ mode: "open" }).append(
            smChip.content.cloneNode(!0)
          ),
          (this._value = void 0),
          (this.radioButton = this.shadowRoot.querySelector("input")),
          (this.fireEvent = this.fireEvent.bind(this)),
          (this.handleKeyDown = this.handleKeyDown.bind(this));
      }
      get value() {
        return this._value;
      }
      fireEvent() {
        this.dispatchEvent(
          new CustomEvent("option-clicked", {
            bubbles: !0,
            composed: !0,
            detail: { value: this._value },
          })
        );
      }
      handleKeyDown(t) {
        ("Enter" !== t.key && "Space" !== t.key) || this.fireEvent();
      }
      connectedCallback() {
        this.setAttribute("role", "option"),
          this.setAttribute("tabindex", "0"),
          (this._value = this.getAttribute("value")),
          this.addEventListener("click", this.fireEvent),
          this.addEventListener("keydown", this.handleKeyDown);
      }
      disconnectedCallback() {
        this.removeEventListener("click", this.fireEvent),
          this.removeEventListener("keydown", this.handleKeyDown);
      }
    }
  );
const smCopy = document.createElement("template");
(smCopy.innerHTML =
  '<style> *{ padding: 0; margin: 0; -webkit-box-sizing: border-box; box-sizing: border-box;} :host{ display: -webkit-box; display: flex; --padding: 0; --button-background-color: rgba(var(--text-color, (17,17,17)), 0.2);}.copy{ display: grid; gap: 0.5rem; padding: var(--padding); align-items: center; grid-template-columns: minmax(0, 1fr) auto;}:host(:not([clip-text])) .copy-content{ overflow-wrap: break-word; word-wrap: break-word;}:host([clip-text]) .copy-content{ overflow: hidden; text-overflow: ellipsis; white-space: nowrap;}.copy-button{ display: inline-flex; justify-content: center; cursor: pointer; border: none; padding: 0.4rem; background-color: rgba(var(--text-color, (17,17,17)), 0.06); border-radius: var(--button-border-radius, 0.3rem); transition: background-color 0.2s; font-family: inherit; color: inherit; font-size: 0.7rem; font-weight: 500; text-transform: uppercase; letter-spacing: 0.05rem;}.copy-button:active{ background-color: var(--button-background-color);}@media (any-hover: hover){ .copy:hover .copy-button{ opacity: 1; } .copy-button:hover{ background-color: var(--button-background-color); }}</style><section class="copy"> <p class="copy-content"> <slot></slot> </p> <button part="button" class="copy-button" title="copy"> <slot name="copy-icon"> COPY </slot> </button></section>'),
  customElements.define(
    "sm-copy",
    class extends HTMLElement {
      constructor() {
        super(),
          this.attachShadow({ mode: "open" }).append(
            smCopy.content.cloneNode(!0)
          ),
          (this.copyContent = this.shadowRoot.querySelector(".copy-content")),
          (this.copyButton = this.shadowRoot.querySelector(".copy-button")),
          (this.copy = this.copy.bind(this));
      }
      static get observedAttributes() {
        return ["value"];
      }
      set value(t) {
        this.setAttribute("value", t);
      }
      get value() {
        return this.getAttribute("value");
      }
      fireEvent() {
        this.dispatchEvent(
          new CustomEvent("copy", { composed: !0, bubbles: !0, cancelable: !0 })
        );
      }
      copy() {
        navigator.clipboard
          .writeText(this.getAttribute("value"))
          .then((t) => this.fireEvent())
          .catch((t) => console.error(t));
      }
      connectedCallback() {
        this.copyButton.addEventListener("click", this.copy);
      }
      attributeChangedCallback(t, n, o) {
        if ("value" === t) {
          const t = this.copyContent.querySelector("slot");
          if (!t) return;
          const n = t.assignedNodes();
          (n && n.length) || (t.textContent = o);
        }
      }
      disconnectedCallback() {
        this.copyButton.removeEventListener("click", this.copy);
      }
    }
  );
const smForm = document.createElement("template");
(smForm.innerHTML =
  ' <style> *{ padding: 0; margin: 0; box-sizing: border-box; } :host{ display: grid; width: 100%; } form{ display: inherit; gap: var(--gap, 1.5rem); width: 100%; } </style> <form part="form" onsubmit="return false"> <slot></slot> </form> '),
  customElements.define(
    "sm-form",
    class extends HTMLElement {
      constructor() {
        super(),
          this.attachShadow({ mode: "open" }).append(
            smForm.content.cloneNode(!0)
          ),
          (this.form = this.shadowRoot.querySelector("form")),
          this.invalidFieldsCount,
          (this.skipSubmit = !1),
          (this.isFormValid = void 0),
          (this.supportedElements =
            "input, sm-input, sm-textarea, sm-checkbox, tags-input, file-input, sm-switch, sm-radio"),
          (this.formElements = []),
          (this._requiredElements = []);
      }
      static get observedAttributes() {
        return ["skip-submit"];
      }
      get validity() {
        return this.isFormValid;
      }
      debounce = (callback, wait) => {
        let timeoutId = null;
        return (...args) => {
          window.clearTimeout(timeoutId),
            (timeoutId = window.setTimeout(() => {
              callback.apply(null, args);
            }, wait));
        };
      };
      _checkValidity = () => {
        this.submitButton &&
          0 !== this._requiredElements.length &&
          ((this.invalidFieldsCount = 0),
          this._requiredElements.forEach(([elem, isWC]) => {
            ((!elem.disabled && isWC && !elem.isValid) ||
              (!isWC && !elem.checkValidity())) &&
              this.invalidFieldsCount++;
          }),
          this.isFormValid !== (0 === this.invalidFieldsCount) &&
            ((this.isFormValid = 0 === this.invalidFieldsCount),
            this.dispatchEvent(
              new CustomEvent(this.isFormValid ? "valid" : "invalid", {
                bubbles: !0,
                composed: !0,
              })
            ),
            this.skipSubmit ||
              (this.submitButton.disabled = !this.isFormValid)));
      };
      handleKeydown = (e) => {
        if ("Enter" === e.key && e.target.tagName.includes("INPUT"))
          if (0 === this.invalidFieldsCount)
            this.submitButton && this.submitButton.click(),
              this.dispatchEvent(
                new CustomEvent("submit", { bubbles: !0, composed: !0 })
              );
          else
            for (const [elem, isWC] of this._requiredElements) {
              if (isWC ? !elem.isValid : !elem.checkValidity()) {
                (elem?.shadowRoot?.lastElementChild || elem).animate(
                  [
                    { transform: "translateX(-1rem)" },
                    { transform: "translateX(1rem)" },
                    { transform: "translateX(-0.5rem)" },
                    { transform: "translateX(0.5rem)" },
                    { transform: "translateX(0)" },
                  ],
                  { duration: 300, easing: "ease" }
                ),
                  isWC
                    ? (elem.focusIn(),
                      "SM-INPUT" === elem.tagName &&
                        "" === elem.value.trim() &&
                        elem.showError())
                    : elem.focus();
                break;
              }
            }
      };
      reset = () => {
        this.formElements.forEach(([elem, isWC]) => {
          if (isWC) elem.reset();
          else
            switch (elem.type) {
              case "checkbox":
              case "radio":
                elem.checked = !1;
                break;
              default:
                elem.value = "";
            }
        }),
          this._checkValidity();
      };
      elementsChanged = () => {
        (this.formElements = [
          ...this.querySelectorAll(this.supportedElements),
        ].map((elem) => [elem, elem.tagName.includes("-")])),
          (this._requiredElements = this.formElements.filter(([elem]) =>
            elem.hasAttribute("required")
          )),
          (this.submitButton = this.querySelector(
            '[variant="primary"], [type="submit"]'
          )),
          (this.resetButton = this.querySelector('[type="reset"]')),
          this.resetButton &&
            this.resetButton.addEventListener("click", this.reset),
          this._checkValidity();
      };
      checkIfSupported = (elem) =>
        1 === elem.nodeType &&
        (elem.tagName.includes("-") ||
          "input" === elem.tagName ||
          elem.querySelector(this.supportedElements));
      connectedCallback() {
        const updateFormDecedents = this.debounce(this.elementsChanged, 100);
        this.addEventListener("input", this.debounce(this._checkValidity, 100)),
          this.addEventListener(
            "keydown",
            this.debounce(this.handleKeydown, 100)
          ),
          this.shadowRoot
            .querySelector("slot")
            .addEventListener("slotchange", updateFormDecedents),
          (this.mutationObserver = new MutationObserver((mutations) => {
            mutations.forEach((mutation) => {
              (("childList" === mutation.type &&
                [...mutation.addedNodes].some((node) =>
                  this.checkIfSupported(node)
                )) ||
                [...mutation.removedNodes].some((node) =>
                  this.checkIfSupported(node)
                )) &&
                updateFormDecedents();
            });
          })),
          this.mutationObserver.observe(this, { childList: !0, subtree: !0 });
      }
      attributeChangedCallback(name, oldValue, newValue) {
        "skip-submit" === name &&
          (this.skipSubmit = this.hasAttribute("skip-submit"));
      }
      disconnectedCallback() {
        this.removeEventListener(
          "input",
          this.debounce(this._checkValidity, 100)
        ),
          this.removeEventListener(
            "keydown",
            this.debounce(this.handleKeydown, 100)
          ),
          this.mutationObserver.disconnect();
      }
    }
  );
const smInput = document.createElement("template");
(smInput.innerHTML =
  ' <style> *{ padding: 0; margin: 0; -webkit-box-sizing: border-box; box-sizing: border-box; }  input[type="search"]::-webkit-search-decoration, input[type="search"]::-webkit-search-cancel-button, input[type="search"]::-webkit-search-results-button, input[type="search"]::-webkit-search-results-decoration { display: none; } input[type=number] { -moz-appearance:textfield; } input[type=number]::-webkit-inner-spin-button,  input[type=number]::-webkit-outer-spin-button {  -webkit-appearance: none; -moz-appearance: none; appearance: none; margin: 0;  } input::-ms-reveal, input::-ms-clear { display: none; } input:invalid{ outline: none; box-shadow: none; } ::-moz-focus-inner{ border: none; } :host{ display: flex; --success-color: #00C853; --danger-color: red; --width: 100%; --icon-gap: 0.5rem; --min-height: 3.2rem; --background: rgba(var(--text-color, (17,17,17)), 0.06); } .hidden{ display: none !important; } button{ display: flex; border: none; background: none; padding: 0; border-radius: 1rem; min-width: 0; cursor: pointer; } button:focus{ outline: var(--accent-color, teal) solid medium; } .icon { height: 1.2rem; width: 1.2rem; fill: rgba(var(--text-color, (17,17,17)), 0.6); }  :host(.round) .input{ border-radius: 10rem; } .outer-container{ display: flex; flex-direction: column; position: relative; width: var(--width); } .input { display: flex; cursor: text; min-width: 0; text-align: left; align-items: center; position: relative; gap: var(--icon-gap); border-radius: var(--border-radius,0.3rem); transition: opacity 0.3s, box-shadow 0.2s; background: var(--background); width: 100%; outline: none; overflow: hidden; min-height: var(--min-height); padding: var(--padding, 0 0.8rem); container: input-wrapper / size; } .input.readonly .clear{ opacity: 0 !important; margin-right: -2rem; pointer-events: none !important; } .readonly{ pointer-events: none; } .input:focus-within:not(.readonly){ box-shadow: 0 0 0 0.1rem var(--accent-color,teal) inset !important; } .disabled{ pointer-events: none; opacity: 0.6; } .placeholder { grid-area: 1/1/2/2; font-size: inherit; opacity: .7; font-weight: 400; transition: transform 0.3s; transform-origin: left; pointer-events: none; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; width: 100%; user-select: none; will-change: transform; } .container{ display: grid; height:100%; width: 100%; grid-template-columns: 1fr auto; position: relative; align-items: center; max-height: 100cqh; }  input{ grid-area: 1/1/2/2; font-size: inherit; border: none; background: transparent; outline: none; color: inherit; font-family: inherit; height: 100%; width: 100%; caret-color: var(--accent-color, teal); font-weight: inherit; padding: var(--input-inner-padding, 0.6rem 0); } .animate-placeholder .container{ padding: var(--input-inner-padding, 0.4rem 0); } .animate-placeholder .container input { grid-row: 2/3; padding: 0; }  .animate-placeholder .placeholder { transform: scale(0.8); opacity: 1; color: var(--accent-color,teal); grid-row: 1/2; } :host([variant="outlined"]) .input { box-shadow: 0 0 0 1px var(--border-color, rgba(var(--text-color, (17,17,17)), 0.3)) inset; background: rgba(var(--background-color, (255,255,255)), 1); } .animate-placeholder:focus-within:not(.readonly) .placeholder{ color: var(--accent-color,teal) } .success{ color: var(--success-color); } .error{ color: var(--danger-color); } .status-icon{ margin-right: 0.5rem; flex-shrink: 0; } .status-icon--error{ fill: var(--danger-color); } .status-icon--success{ fill: var(--success-color); } .datalist{ position: absolute; top: 100%; left: 0; width: 100%; z-index: 100; background: rgba(var(--foreground-color, (255,255,255)), 1); border-radius: 0 0 var(--border-radius,0.5rem) var(--border-radius,0.5rem); box-shadow: 0 0.5rem 1rem rgba(0,0,0,0.1); max-height: 20rem; overflow-y: auto; overflow-x: hidden; padding: 0.3rem; } .datalist-item{ padding: 0.8rem 1rem; cursor: pointer; transition: background 0.2s; border-radius: 0.5rem; content-visibility: auto; } .datalist-item:focus{ outline: none; } .datalist-item:focus-visible{ outline: var(--accent-color, teal) solid medium; } @media (any-hover: hover){ .icon:hover{ background: rgba(var(--text-color, (17,17,17)), 0.1); } .datalist-item:hover{ background: rgba(var(--text-color, (17,17,17)), 0.06); } } </style> <div class="outer-container"> <div part="input-wrapper" class="input"> <slot name="icon"></slot> <label class="container"> <span part="placeholder" class="placeholder"></span> <input part="input" type="text"/> </label> <button class="clear hidden" title="Clear" tabindex="-1"> <svg class="icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="24" height="24"><path fill="none" d="M0 0h24v24H0z"/><path d="M12 22C6.477 22 2 17.523 2 12S6.477 2 12 2s10 4.477 10 10-4.477 10-10 10zm0-11.414L9.172 7.757 7.757 9.172 10.586 12l-2.829 2.828 1.415 1.415L12 13.414l2.828 2.829 1.415-1.415L13.414 12l2.829-2.828-1.415-1.415L12 10.586z"/></svg> </button> <slot name="right"></slot> </div> <ul class="datalist hidden" part="datalist"></ul> </div> '),
  customElements.define(
    "sm-input",
    class SmInput extends HTMLElement {
      static hasAppendedStyles = !1;
      #validationState = {
        validatedFor: void 0,
        isValid: !1,
        errorMessage: "Please fill out this field.",
      };
      constructor() {
        super(),
          this.attachShadow({ mode: "open" }).append(
            smInput.content.cloneNode(!0)
          ),
          (this.inputParent = this.shadowRoot.querySelector(".input")),
          (this.input = this.shadowRoot.querySelector("input")),
          (this.clearBtn = this.shadowRoot.querySelector(".clear")),
          (this.placeholderElement =
            this.shadowRoot.querySelector(".placeholder")),
          (this.outerContainer =
            this.shadowRoot.querySelector(".outer-container")),
          (this.optionList = this.shadowRoot.querySelector(".datalist")),
          (this._helperText = ""),
          (this.isRequired = !1),
          (this.datalist = []),
          (this.validationFunction = void 0),
          (this.reflectedAttributes = [
            "value",
            "required",
            "disabled",
            "type",
            "inputmode",
            "readonly",
            "min",
            "max",
            "pattern",
            "minlength",
            "maxlength",
            "step",
            "list",
            "autocomplete",
          ]);
      }
      static get observedAttributes() {
        return [
          "value",
          "placeholder",
          "required",
          "disabled",
          "type",
          "inputmode",
          "readonly",
          "min",
          "max",
          "pattern",
          "minlength",
          "maxlength",
          "step",
          "helper-text",
          "error-text",
          "list",
        ];
      }
      get value() {
        return this.input.value;
      }
      set value(val) {
        val !== this.input.value &&
          ((this.input.value = val), (this._value = val), this.checkInput());
      }
      get placeholder() {
        return this.getAttribute("placeholder");
      }
      set placeholder(val) {
        this.setAttribute("placeholder", val);
      }
      get type() {
        return this.getAttribute("type");
      }
      set type(val) {
        this.setAttribute("type", val);
      }
      get validity() {
        return this.input.validity;
      }
      get disabled() {
        return this.hasAttribute("disabled");
      }
      set disabled(value) {
        value
          ? (this.inputParent.classList.add("disabled"),
            this.setAttribute("disabled", ""))
          : (this.inputParent.classList.remove("disabled"),
            this.removeAttribute("disabled"));
      }
      get readOnly() {
        return this.hasAttribute("readonly");
      }
      set readOnly(value) {
        value
          ? this.setAttribute("readonly", "")
          : this.removeAttribute("readonly");
      }
      set customValidation(val) {
        val && (this.validationFunction = val);
      }
      set errorText(val) {
        this.#validationState.errorText = val;
      }
      showError = (errorText = this.#validationState.errorText) => {
        const appendedNew = this.appendFeedbackElement();
        (this.feedbackPopover.innerHTML = ` <svg class="status-icon status-icon--error" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="24" height="24"><path fill="none" d="M0 0h24v24H0z"/><path d="M12 22C6.477 22 2 17.523 2 12S6.477 2 12 2s10 4.477 10 10-4.477 10-10 10zm-1-7v2h2v-2h-2zm0-8v6h2V7h-2z"/></svg> ${errorText} `),
          (this.feedbackPopover.dataset.state = "error"),
          appendedNew &&
            this.feedbackPopover.animate(
              [
                { transform: "scale(0.95)", opacity: 0 },
                { transform: "scale(1)", opacity: 1 },
              ],
              { duration: 200, easing: "ease", fill: "forwards" }
            );
      };
      set helperText(val) {
        this._helperText = val;
      }
      get isValid() {
        if (this.#validationState.validatedFor === this.input.value)
          return this.#validationState.isValid;
        const _isValid = this.input.checkValidity();
        let _validity = { isValid: !0, errorText: "" };
        return (
          this.validationFunction &&
            (_validity = this.validationFunction(this.input.value)),
          _isValid && _validity.isValid
            ? (this.setAttribute("valid", ""),
              this.removeAttribute("invalid"),
              this.hideFeedback())
            : (this.removeAttribute("valid"),
              this.setAttribute("invalid", ""),
              "" !== this.value.trim() &&
                (_validity.errorText || this.#validationState.errorText) &&
                this.showError(
                  _validity.errorText || this.#validationState.errorText
                )),
          (this.#validationState.validatedFor = this.input.value),
          (this.#validationState.isValid = _isValid && _validity.isValid),
          (this.#validationState.errorText =
            _validity.errorText || this.#validationState.errorText),
          this.#validationState.isValid
        );
      }
      reset = () => {
        this.value = "";
      };
      clear = () => {
        (this.value = ""), this.input.focus(), this.fireEvent();
      };
      focusIn = () => {
        this.input.focus();
      };
      focusOut = () => {
        this.input.blur();
      };
      fireEvent = () => {
        let event = new Event("input", {
          bubbles: !0,
          cancelable: !0,
          composed: !0,
        });
        this.dispatchEvent(event);
      };
      searchDatalist = (searchKey) => {
        const filteredData = this.datalist.filter((item) =>
          item.toLowerCase().includes(searchKey.toLowerCase())
        );
        if (
          (filteredData.sort(
            (a, b) =>
              a.toLowerCase().indexOf(searchKey.toLowerCase()) -
              b.toLowerCase().indexOf(searchKey.toLowerCase())
          ),
          filteredData.length)
        ) {
          if (this.optionList.children.length > filteredData.length) {
            const optionsToRemove =
              this.optionList.children.length - filteredData.length;
            for (let i = 0; i < optionsToRemove; i++)
              this.optionList.removeChild(this.optionList.lastChild);
          }
          filteredData.forEach((item, index) => {
            if (this.optionList.children[index])
              this.optionList.children[index].textContent = item;
            else {
              const option = document.createElement("li");
              (option.textContent = item),
                option.classList.add("datalist-item"),
                option.setAttribute("tabindex", "0"),
                this.optionList.appendChild(option);
            }
          }),
            this.optionList.classList.remove("hidden");
        } else this.optionList.classList.add("hidden");
      };
      checkInput = (e) => {
        this.hasAttribute("readonly") ||
          ("" !== this.input.value
            ? this.clearBtn.classList.remove("hidden")
            : this.clearBtn.classList.add("hidden")),
          this.hasAttribute("placeholder") &&
            "" !== this.getAttribute("placeholder").trim() &&
            ("" !== this.input.value
              ? (this.shouldAnimatePlaceholder &&
                  this.inputParent.classList.add("animate-placeholder"),
                this.placeholderElement.classList.toggle(
                  "hidden",
                  !this.shouldAnimatePlaceholder
                ),
                this.datalist.length &&
                  (this.searchTimeout && clearTimeout(this.searchTimeout),
                  (this.searchTimeout = setTimeout(() => {
                    this.searchDatalist(this.input.value.trim());
                  }, 100))))
              : (this.shouldAnimatePlaceholder &&
                  this.inputParent.classList.remove("animate-placeholder"),
                this.placeholderElement.classList.remove("hidden"),
                this.hideFeedback(),
                this.datalist.length &&
                  ((this.optionList.innerHTML = ""),
                  this.optionList.classList.add("hidden"))));
      };
      allowOnlyNum = (e) => {
        e.ctrlKey ||
          (1 === e.key.length &&
            ((("." !== e.key ||
              (!e.target.value.includes(".") && 0 !== e.target.value.length)) &&
              ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "."].includes(
                e.key
              )) ||
              e.preventDefault()));
      };
      handleOptionClick = (e) => {
        (this.input.value = e.target.textContent),
          this.optionList.classList.add("hidden"),
          this.input.focus();
      };
      handleInputNavigation = (e) => {
        "ArrowDown" === e.key
          ? (e.preventDefault(),
            this.optionList.children.length &&
              this.optionList.children[0].focus())
          : "ArrowUp" === e.key &&
            (e.preventDefault(),
            this.optionList.children.length &&
              this.optionList.children[
                this.optionList.children.length - 1
              ].focus());
      };
      handleDatalistNavigation = (e) => {
        "ArrowUp" === e.key
          ? (e.preventDefault(),
            this.shadowRoot.activeElement.previousElementSibling
              ? this.shadowRoot.activeElement.previousElementSibling.focus()
              : this.input.focus())
          : "ArrowDown" === e.key
          ? (e.preventDefault(),
            this.shadowRoot.activeElement.nextElementSibling
              ? this.shadowRoot.activeElement.nextElementSibling.focus()
              : this.input.focus())
          : ("Enter" !== e.key && " " !== e.key) ||
            (e.preventDefault(),
            (this.input.value = e.target.textContent),
            this.optionList.classList.add("hidden"),
            this.input.focus());
      };
      handleFocus = (e) => {
        this.datalist.length && this.searchDatalist(this.input.value.trim());
      };
      handleBlur = (e) => {
        this.datalist.length && this.optionList.classList.add("hidden");
      };
      applyGlobalCustomValidation = () => {
        if (void 0 !== window.smCompConfig && window.smCompConfig["sm-input"]) {
          const config = window.smCompConfig["sm-input"].find((config) =>
            this.matches(config.selector)
          );
          this.customValidation = config?.customValidation;
        }
      };
      updatePosition = () => {
        requestAnimationFrame(() => {
          if (
            ((this.dimensions = this.getBoundingClientRect()),
            (this.scrollingParentDimensions =
              this.scrollingParent.getBoundingClientRect()),
            0 === this.dimensions.width || 0 === this.dimensions.height)
          )
            return;
          let topOffset =
              this.dimensions.top -
              this.scrollingParentDimensions.top +
              this.dimensions.height,
            leftOffset =
              this.dimensions.left - this.scrollingParentDimensions.left;
          const maxWidth = this.dimensions.width;
          this.feedbackPopover.style = `top: ${topOffset}px; left: ${leftOffset}px; max-width: ${maxWidth}px;`;
        });
      };
      appendFeedbackElement = () => {
        if (this.feedbackPopover) return !1;
        (this.feedbackPopover = document.createElement("div")),
          (this.feedbackPopover.className = "feedback-popover"),
          this.feedbackPopover.setAttribute("aria-live", "polite"),
          (this.containment = this.closest("[data-sm-containment]")),
          (this.scrollingParent = this.getNearestScrollingParent(this));
        return (
          (this.containment || this.scrollingParent).appendChild(
            this.feedbackPopover
          ),
          "" === this.scrollingParent.style.position &&
            (this.scrollingParent.style.position = "relative"),
          this.containment ||
            ((this.observerHidFeedback = !1),
            (this.intersectionObserver = new IntersectionObserver((entries) => {
              if (this.feedbackPopover)
                if (entries[0].isIntersecting) {
                  if (!this.observerHidFeedback) return;
                  this.feedbackPopover.classList.remove("hidden"),
                    (this.observerHidFeedback = !1);
                } else
                  this.feedbackPopover.classList.add("hidden"),
                    (this.observerHidFeedback = !0);
            }).observe(this))),
          this.updatePosition(),
          window.addEventListener("resize", this.updatePosition, {
            passive: !0,
          }),
          !0
        );
      };
      getNearestScrollingParent = (element) => {
        let parent = element.parentNode;
        for (; parent; ) {
          if (
            parent.scrollHeight > parent.clientHeight ||
            parent.scrollWidth > parent.clientWidth ||
            parent.tagName.includes("SM-") ||
            parent.hasAttribute("data-scrollable")
          )
            return parent;
          parent = parent.parentNode;
        }
        return document.body;
      };
      hideFeedback = () => {
        this.feedbackPopover &&
          (this.feedbackPopover.animate(
            [
              { transform: "none", opacity: 1 },
              { transform: "scale(0.95)", opacity: 0 },
            ],
            { duration: 100, easing: "ease-in-out", fill: "forwards" }
          ).onfinish = () => {
            this.intersectionObserver?.disconnect(),
              this.feedbackPopover.remove(),
              (this.feedbackPopover = null),
              window.removeEventListener("resize", this.updatePosition, {
                passive: !0,
              });
          });
      };
      connectedCallback() {
        SmInput.hasAppendedStyles ||
          (document.head.insertAdjacentHTML(
            "beforeend",
            "<style> // styles injected by sm-input component .success{ color: var(--success-color); } .error{ color: var(--danger-color); } .status-icon{ margin-right: 0.5rem; flex-shrink: 0; } .status-icon--error{ fill: var(--danger-color); } .status-icon--success{ fill: var(--success-color); } .feedback-popover:not(:empty){ position: absolute; display: flex; width: fit-content; top: 100%; text-align: left; font-size: 0.9rem; align-items: center; padding: 0.8rem; border-radius: var(--border-radius,0.5rem); color: rgba(var(--text-color, (17,17,17)), 0.8); background: rgba(var(--foreground-color, (255,255,255)), 1); margin-top: 0.5rem; box-shadow: 0 0.5rem 1rem rgba(var(--text-color, (17,17,17)), 0.1); } .feedback-popover:not(:empty)::before{ content: ''; height: 0; width: 0; position: absolute; border: 0.5rem solid transparent; border-bottom-color: rgba(var(--foreground-color, (255,255,255)), 1); top: -1rem; left: 1rem; } </style>"
          ),
          (SmInput.hasAppendedStyles = !0)),
          (this.shouldAnimatePlaceholder = this.hasAttribute("animate")),
          this.shouldAnimatePlaceholder &&
            "" !== this.placeholderElement &&
            this.value &&
            (this.inputParent.classList.add("animate-placeholder"),
            this.placeholderElement.classList.remove("hidden")),
          this.setAttribute("role", "textbox"),
          "loading" === document.readyState
            ? window.addEventListener(
                "load",
                this.applyGlobalCustomValidation,
                { once: !0 }
              )
            : this.applyGlobalCustomValidation(),
          this.input.addEventListener("input", this.checkInput),
          this.clearBtn.addEventListener("click", this.clear),
          this.datalist.length &&
            (this.optionList.addEventListener("click", this.handleOptionClick),
            this.input.addEventListener("keydown", this.handleInputNavigation),
            this.optionList.addEventListener(
              "keydown",
              this.handleDatalistNavigation
            )),
          this.input.addEventListener("focusin", this.handleFocus),
          this.addEventListener("focusout", this.handleBlur);
      }
      attributeChangedCallback(name, oldValue, newValue) {
        if (oldValue !== newValue)
          switch (
            (this.reflectedAttributes.includes(name) &&
              (this.hasAttribute(name)
                ? this.input.setAttribute(
                    name,
                    this.getAttribute(name) ? this.getAttribute(name) : ""
                  )
                : this.input.removeAttribute(name)),
            name)
          ) {
            case "placeholder":
              (this.placeholderElement.textContent = newValue),
                this.setAttribute("aria-label", newValue);
              break;
            case "value":
              this.checkInput();
              break;
            case "type":
              this.hasAttribute("type") &&
              "number" === this.getAttribute("type")
                ? (this.input.setAttribute("inputmode", "decimal"),
                  this.input.addEventListener("keydown", this.allowOnlyNum))
                : this.input.removeEventListener("keydown", this.allowOnlyNum);
              break;
            case "helper-text":
              this._helperText = newValue;
              break;
            case "error-text":
              this.#validationState.errorText = newValue;
              break;
            case "required":
              (this.isRequired = this.hasAttribute("required")),
                this.isRequired
                  ? this.setAttribute("aria-required", "true")
                  : this.setAttribute("aria-required", "false");
              break;
            case "readonly":
              this.hasAttribute("readonly")
                ? this.inputParent.classList.add("readonly")
                : this.inputParent.classList.remove("readonly");
              break;
            case "disabled":
              this.hasAttribute("disabled")
                ? this.inputParent.classList.add("disabled")
                : this.inputParent.classList.remove("disabled");
              break;
            case "list":
              this.hasAttribute("list") &&
                "" !== this.getAttribute("list").trim() &&
                (this.datalist = this.getAttribute("list").split(","));
          }
      }
      disconnectedCallback() {
        this.input.removeEventListener("input", this.checkInput),
          this.clearBtn.removeEventListener("click", this.clear),
          this.input.removeEventListener("keydown", this.allowOnlyNum),
          this.optionList.removeEventListener("click", this.handleOptionClick),
          this.input.removeEventListener("keydown", this.handleInputNavigation),
          this.optionList.removeEventListener(
            "keydown",
            this.handleDatalistNavigation
          ),
          this.input.removeEventListener("focusin", this.handleFocus),
          this.removeEventListener("focusout", this.handleBlur),
          window.removeEventListener("resize", this.updatePosition, {
            passive: !0,
          }),
          this.feedbackPopover && this.feedbackPopover.remove(),
          this.intersectionObserver && this.intersectionObserver.disconnect();
      }
    }
  );
const smNotifications = document.createElement("template");
(smNotifications.innerHTML =
  " <style> *{ padding: 0; margin: 0; -webkit-box-sizing: border-box; box-sizing: border-box; }  :host{ display: flex; --icon-height: 1.5rem; --icon-width: 1.5rem; } .hide{ opacity: 0 !important; pointer-events: none !important; } .notification-panel{ display: grid; width: min(26rem, 100%); gap: 0.5rem; position: fixed; left: 0; top: 0; z-index: 100; max-height: 100%; padding: 1rem; overflow: hidden auto; overscroll-behavior: contain; touch-action: none; } .notification-panel:empty{ display:none; } .notification{ display: flex; position: relative; border-radius: 0.5rem; background: rgba(var(--foreground-color, (255,255,255)), 1); overflow: hidden; overflow-wrap: break-word; word-wrap: break-word; word-break: break-word; padding: max(1rem,1.5vw); align-items: center; box-shadow: 0 0.5rem 1rem 0 rgba(0,0,0,0.14); touch-action: none; } .notification:not(.pinned)::before{ content: ''; position: absolute; bottom: 0; left: 0; height: 0.2rem; width: 100%; background-color: var(--accent-color, teal); animation: loading var(--timeout, 5000ms) linear forwards; transform-origin: left; } @keyframes loading{ to{ transform: scaleX(0); } } .icon-container:not(:empty){ margin-right: 0.5rem; height: var(--icon-height); width: var(--icon-width); flex-shrink: 0; } .notification:last-of-type{ margin-bottom: 0; } .icon { height: 100%; width: 100%; fill: rgba(var(--text-color, (17,17,17)), 0.7); } .icon--success { fill: var(--green); } .icon--failure, .icon--error { fill: var(--danger-color); } output{ width: 100%; } .close{ height: 2rem; width: 2rem; border: none; cursor: pointer; margin-left: 1rem; border-radius: 50%; padding: 0.3rem; transition: background-color 0.3s, transform 0.3s; background-color: transparent; flex-shrink: 0; } .close:active{ transform: scale(0.9); } .action{ display: flex; align-items: center; justify-content: center; padding: 0.5rem 0.8rem; border-radius: 0.2rem; border: none; background-color: rgba(var(--text-color, (17,17,17)), 0.03); font-family: inherit; font-size: inherit; color: var(--accent-color, teal); font-weight: 500; cursor: pointer; } @media screen and (max-width: 640px){ .close{ display: none; } .notification-panel:not(:empty){ padding-bottom: 3rem; } } @media screen and (min-width: 640px){ .notification-panel{ top: auto; bottom: 0; max-width: max-content; } .notification{ width: auto; max-width: max-content;  border: solid 1px rgba(var(--text-color, (17,17,17)), 0.2); } } @media (any-hover: hover){ ::-webkit-scrollbar{ width: 0.5rem; }  ::-webkit-scrollbar-thumb{ background: rgba(var(--text-color, (17,17,17)), 0.3); border-radius: 1rem; &:hover{ background: rgba(var(--text-color, (17,17,17)), 0.5); } } .close:hover{ background-color: rgba(var(--text-color, (17,17,17)), 0.1); } } </style> <div class=\"notification-panel\"></div> "),
  customElements.define(
    "sm-notifications",
    class extends HTMLElement {
      constructor() {
        super(),
          (this.shadow = this.attachShadow({ mode: "open" }).append(
            smNotifications.content.cloneNode(!0)
          )),
          (this.notificationPanel = this.shadowRoot.querySelector(
            ".notification-panel"
          )),
          (this.animationOptions = {
            duration: 300,
            fill: "forwards",
            easing: "cubic-bezier(0.175, 0.885, 0.32, 1.275)",
          }),
          (this.push = this.push.bind(this)),
          (this.createNotification = this.createNotification.bind(this)),
          (this.removeNotification = this.removeNotification.bind(this)),
          (this.clearAll = this.clearAll.bind(this)),
          (this.remove = this.remove.bind(this)),
          (this.handleTouchMove = this.handleTouchMove.bind(this)),
          (this.startX = 0),
          (this.currentX = 0),
          (this.endX = 0),
          (this.swipeDistance = 0),
          (this.swipeDirection = ""),
          (this.swipeThreshold = 0),
          (this.startTime = 0),
          (this.swipeTime = 0),
          (this.swipeTimeThreshold = 200),
          (this.currentTarget = null),
          (this.notificationTimeout = 5e3),
          (this.mediaQuery = window.matchMedia("(min-width: 640px)")),
          (this.handleOrientationChange =
            this.handleOrientationChange.bind(this)),
          (this.isBigViewport = !1);
      }
      set timeout(value) {
        isNaN(value) || (this.notificationTimeout = value);
      }
      randString(length) {
        let result = "";
        const characters =
          "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        for (let i = 0; i < length; i++)
          result += characters.charAt(Math.floor(52 * Math.random()));
        return result;
      }
      createNotification(message, options = {}) {
        const {
            pinned: pinned = !1,
            icon: icon,
            action: action,
            timeout: timeout = this.notificationTimeout,
          } = options,
          notification = document.createElement("div");
        return (
          (notification.id = this.randString(8)),
          (notification.className = "notification " + (pinned ? "pinned" : "")),
          notification.style.setProperty("--timeout", `${timeout}ms`),
          (notification.innerHTML = ` ${
            icon ? `<div class="icon-container">${icon}</div>` : ""
          } <output>${message}</output> ${
            action ? `<button class="action">${action.label}</button>` : ""
          } <button class="close"> <svg class="icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="24" height="24"><path fill="none" d="M0 0h24v24H0z"/><path d="M12 10.586l4.95-4.95 1.414 1.414-4.95 4.95 4.95 4.95-1.414 1.414-4.95-4.95-4.95 4.95-1.414-1.414 4.95-4.95-4.95-4.95L7.05 5.636z"/></svg> </button> `),
          action &&
            notification
              .querySelector(".action")
              .addEventListener("click", action.callback),
          notification.querySelector(".close").addEventListener("click", () => {
            this.removeNotification(notification);
          }),
          pinned ||
            setTimeout(() => {
              this.removeNotification(
                notification,
                this.isBigViewport ? "left" : "top"
              );
            }, timeout),
          notification
        );
      }
      push(message, options = {}) {
        const notification = this.createNotification(message, options);
        return (
          this.isBigViewport
            ? this.notificationPanel.append(notification)
            : this.notificationPanel.prepend(notification),
          notification.scrollIntoView({ behavior: "smooth" }),
          this.notificationPanel.animate(
            [
              {
                transform: `translateY(${this.isBigViewport ? "" : "-"}${
                  notification.clientHeight
                }px)`,
              },
              { transform: "none" },
            ],
            this.animationOptions
          ),
          (notification.animate(
            [
              { transform: "translateY(-1rem)", opacity: "0" },
              { transform: "none", opacity: "1" },
            ],
            this.animationOptions
          ).onfinish = (e) => {
            e.target.commitStyles(), e.target.cancel();
          }),
          notification.id
        );
      }
      removeNotification(notification, direction = "left") {
        if (!notification) return;
        const sign = "left" === direction || "top" === direction ? "-" : "+";
        this.isBigViewport || "top" !== direction
          ? (notification.animate(
              [
                {
                  transform: this.currentX
                    ? `translateX(${this.currentX}px)`
                    : "none",
                  opacity: "1",
                },
                {
                  transform: `translateX(calc(${sign}${Math.abs(
                    this.currentX
                  )}px ${sign} 1rem))`,
                  opacity: "0",
                },
              ],
              this.animationOptions
            ).onfinish = () => {
              notification.remove();
            })
          : (notification.animate(
              [
                {
                  transform: this.currentX
                    ? `translateY(${this.currentX}px)`
                    : "none",
                  opacity: "1",
                },
                {
                  transform: `translateY(calc(${sign}${Math.abs(
                    this.currentX
                  )}px ${sign} 1rem))`,
                  opacity: "0",
                },
              ],
              this.animationOptions
            ).onfinish = () => {
              notification.remove();
            });
      }
      remove(id) {
        const notification = this.notificationPanel.querySelector(`#${id}`);
        notification && this.removeNotification(notification);
      }
      clearAll() {
        Array.from(this.notificationPanel.children).forEach((child) => {
          this.removeNotification(child);
        });
      }
      handleTouchMove(e) {
        (this.currentX = e.touches[0].clientX - this.startX),
          (this.currentTarget.style.transform = `translateX(${this.currentX}px)`);
      }
      handleOrientationChange(e) {
        (this.isBigViewport = e.matches), e.matches;
      }
      connectedCallback() {
        this.handleOrientationChange(this.mediaQuery),
          this.mediaQuery.addEventListener(
            "change",
            this.handleOrientationChange
          ),
          this.notificationPanel.addEventListener(
            "touchstart",
            (e) => {
              e.target.closest(".close")
                ? this.removeNotification(e.target.closest(".notification"))
                : e.target.closest(".notification") &&
                  ((this.swipeThreshold =
                    e.target.closest(".notification").getBoundingClientRect()
                      .width / 2),
                  (this.currentTarget = e.target.closest(".notification")),
                  (this.startTime = Date.now()),
                  (this.startX = e.touches[0].clientX),
                  (this.startY = e.touches[0].clientY),
                  this.notificationPanel.addEventListener(
                    "touchmove",
                    this.handleTouchMove,
                    { passive: !0 }
                  ));
            },
            { passive: !0 }
          ),
          this.notificationPanel.addEventListener("touchend", (e) => {
            (this.endX = e.changedTouches[0].clientX),
              (this.endY = e.changedTouches[0].clientY),
              (this.swipeDistance = Math.abs(this.endX - this.startX)),
              (this.swipeTime = Date.now() - this.startTime),
              this.endX > this.startX
                ? (this.swipeDirection = "right")
                : (this.swipeDirection = "left"),
              this.swipeTime < this.swipeTimeThreshold
                ? this.swipeDistance > 50 &&
                  this.removeNotification(
                    this.currentTarget,
                    this.swipeDirection
                  )
                : this.swipeDistance > this.swipeThreshold
                ? this.removeNotification(
                    this.currentTarget,
                    this.swipeDirection
                  )
                : (this.currentTarget.animate(
                    [
                      { transform: `translateX(${this.currentX}px)` },
                      { transform: "none" },
                    ],
                    this.animationOptions
                  ).onfinish = (e) => {
                    e.target.commitStyles(), e.target.cancel();
                  }),
              this.notificationPanel.removeEventListener(
                "touchmove",
                this.handleTouchMove
              ),
              (this.currentX = 0);
          });
      }
      disconnectedCallback() {
        mediaQueryList.removeEventListener("change", handleOrientationChange);
      }
    }
  );
class Stack {
  constructor() {
    this.items = [];
  }
  push(element) {
    this.items.push(element);
  }
  pop() {
    return 0 == this.items.length ? "Underflow" : this.items.pop();
  }
  peek() {
    return this.items[this.items.length - 1];
  }
}
const popupStack = new Stack(),
  smPopup = document.createElement("template");
(smPopup.innerHTML =
  '<style>*{ padding: 0; margin: 0; -webkit-box-sizing: border-box; box-sizing: border-box;} :host{ position: fixed; display: -ms-grid; display: grid; z-index: 10; --width: 100%; --height: auto; --min-width: auto; --min-height: auto; --backdrop-background: rgba(0, 0, 0, 0.6); --border-radius: 0.8rem 0.8rem 0 0;}.popup-container{ display: -ms-grid; display: grid; position: fixed; top: 0; bottom: 0; left: 0; right: 0; place-items: center; z-index: 10; touch-action: none;}:host(.stacked) .popup{ -webkit-transform: scale(0.9) translateY(-2rem) !important; transform: scale(0.9) translateY(-2rem) !important;}.backdrop{ position: absolute; top: 0; bottom: 0; left: 0; right: 0; background: var(--backdrop-background); -webkit-transition: opacity 0.3s; -o-transition: opacity 0.3s; transition: opacity 0.3s;}.popup{ display: -webkit-box; display: -ms-flexbox; display: flex; -webkit-box-orient: vertical; -webkit-box-direction: normal; flex-direction: column; position: relative; -ms-flex-item-align: end; align-self: flex-end; -webkit-box-align: start; -ms-flex-align: start; align-items: flex-start; width: var(--width); min-width: var(--min-width); height: var(--height); min-height: var(--min-height); max-height: 90vh; border-radius: var(--border-radius); background: rgba(var(--background-color, (255,255,255)), 1); -webkit-box-shadow: 0 -1rem 2rem #00000020; box-shadow: 0 -1rem 2rem #00000020;}.container-header{ display: -webkit-box; display: flex; width: 100%; touch-action: none; -webkit-box-align: center; -ms-flex-align: center; align-items: center;}.popup-top{ display: -webkit-box; display: flex; width: 100%;}.popup-body{ display: -webkit-box; display: flex; -webkit-box-orient: vertical; -webkit-box-direction: normal; -ms-flex-direction: column; flex-direction: column; -webkit-box-flex: 1; -ms-flex: 1; flex: 1; width: 100%; padding: var(--body-padding, 1.5rem); overflow-y: auto;}.hide{ display:none;}@media screen and (min-width: 640px){ :host{ --border-radius: 0.5rem; } .popup{ -ms-flex-item-align: center; -ms-grid-row-align: center; align-self: center; border-radius: var(--border-radius); height: var(--height); -webkit-box-shadow: 0 3rem 2rem -0.5rem #00000040; box-shadow: 0 3rem 2rem -0.5rem #00000040; }}@media screen and (max-width: 640px){ .popup-top{ -webkit-box-orient: vertical; -webkit-box-direction: normal; flex-direction: column; -webkit-box-align: center; align-items: center; } .handle{ height: 0.3rem; width: 2rem; background: rgba(var(--text-color, (17,17,17)), .4); border-radius: 1rem; margin: 0.5rem 0; }}@media (any-hover: hover){ ::-webkit-scrollbar{ width: 0.5rem; }  ::-webkit-scrollbar-thumb{ background: rgba(var(--text-color, (17,17,17)), 0.3); border-radius: 1rem; &:hover{ background: rgba(var(--text-color, (17,17,17))), 0.5); } }}</style><div class="popup-container hide" role="dialog"> <div part="backdrop" class="backdrop"></div> <div part="popup" class="popup"> <div part="popup-header" class="popup-top"> <div class="handle"></div> <slot name="header"></slot> </div> <div part="popup-body" class="popup-body"> <slot></slot> </div> </div></div>'),
  customElements.define(
    "sm-popup",
    class extends HTMLElement {
      constructor() {
        super(),
          this.attachShadow({ mode: "open" }).append(
            smPopup.content.cloneNode(!0)
          ),
          (this.allowClosing = !1),
          (this.isOpen = !1),
          (this.offset = 0),
          (this.touchStartY = 0),
          (this.touchEndY = 0),
          (this.touchStartTime = 0),
          (this.touchEndTime = 0),
          (this.touchEndAnimation = void 0),
          this.focusable,
          this.autoFocus,
          this.mutationObserver,
          (this.popupContainer =
            this.shadowRoot.querySelector(".popup-container")),
          (this.backdrop = this.shadowRoot.querySelector(".backdrop")),
          (this.dialogBox = this.shadowRoot.querySelector(".popup")),
          (this.popupBodySlot =
            this.shadowRoot.querySelector(".popup-body slot")),
          (this.popupHeader = this.shadowRoot.querySelector(".popup-top"));
      }
      static get observedAttributes() {
        return ["open"];
      }
      get open() {
        return this.isOpen;
      }
      animateTo = (element, keyframes, options) => {
        const anime = element.animate(keyframes, { ...options, fill: "both" });
        return (
          anime.finished.then(() => {
            anime.commitStyles(), anime.cancel();
          }),
          anime
        );
      };
      resumeScrolling = () => {
        const scrollY = document.body.style.top;
        window.scrollTo(0, -1 * parseInt(scrollY || "0")),
          (document.body.style.overflow = ""),
          (document.body.style.top = "initial");
      };
      setStateOpen = () => {
        if (!this.isOpen || this.offset) {
          const animOptions = { duration: 300, easing: "ease" },
            initialAnimation =
              window.innerWidth > 640
                ? "scale(1.1)"
                : `translateY(${this.offset ? `${this.offset}px` : "100%"})`;
          this.animateTo(
            this.dialogBox,
            [
              { opacity: this.offset ? 1 : 0, transform: initialAnimation },
              { opacity: 1, transform: "none" },
            ],
            animOptions
          );
        }
      };
      show = (options = {}) => {
        const { pinned: pinned = !1, payload: payload } = options;
        if (this.isOpen) return;
        const animOptions = { duration: 300, easing: "ease" };
        return (
          (this.payload = payload),
          popupStack.push({ popup: this, permission: pinned }),
          popupStack.items.length > 1 &&
            this.animateTo(
              popupStack.items[
                popupStack.items.length - 2
              ].popup.shadowRoot.querySelector(".popup"),
              [
                { transform: "none" },
                {
                  transform:
                    window.innerWidth > 640
                      ? "scale(0.95)"
                      : "translateY(-1.5rem)",
                },
              ],
              animOptions
            ),
          this.popupContainer.classList.remove("hide"),
          this.offset ||
            ((this.backdrop.animate(
              [{ opacity: 0 }, { opacity: 1 }],
              animOptions
            ).onfinish = () => {
              this.resolveOpen(this.payload);
            }),
            this.dispatchEvent(
              new CustomEvent("popupopened", {
                bubbles: !0,
                composed: !0,
                detail: { payload: this.payload },
              })
            ),
            (document.body.style.overflow = "hidden"),
            (document.body.style.top = `-${window.scrollY}px`)),
          this.setStateOpen(),
          (this.pinned = pinned),
          (this.isOpen = !0),
          setTimeout(() => {
            const elementToFocus =
              this.autoFocus || this.focusable?.[0] || this.dialogBox;
            elementToFocus &&
              (elementToFocus.tagName.includes("-")
                ? elementToFocus.focusIn()
                : elementToFocus.focus());
          }, 0),
          this.hasAttribute("open") ||
            (this.setAttribute("open", ""),
            this.addEventListener("keydown", this.detectFocus),
            this.resizeObserver.observe(this),
            this.mutationObserver.observe(this, {
              attributes: !0,
              childList: !0,
              subtree: !0,
            }),
            this.popupHeader.addEventListener(
              "touchstart",
              this.handleTouchStart,
              { passive: !0 }
            ),
            this.backdrop.addEventListener(
              "mousedown",
              this.handleSoftDismiss
            )),
          {
            opened: new Promise((resolve) => {
              this.resolveOpen = resolve;
            }),
            closed: new Promise((resolve) => {
              this.resolveClose = resolve;
            }),
          }
        );
      };
      hide = (options = {}) => {
        const { payload: payload } = options,
          animOptions = { duration: 150, easing: "ease" };
        this.backdrop.animate([{ opacity: 1 }, { opacity: 0 }], animOptions),
          this.animateTo(
            this.dialogBox,
            [
              {
                opacity: 1,
                transform:
                  window.innerWidth > 640
                    ? "none"
                    : `translateY(${this.offset ? `${this.offset}px` : "0"})`,
              },
              {
                opacity: 0,
                transform:
                  window.innerWidth > 640 ? "scale(1.1)" : "translateY(100%)",
              },
            ],
            animOptions
          ).finished.finally(() => {
            this.popupContainer.classList.add("hide"),
              (this.dialogBox.style = ""),
              this.removeAttribute("open"),
              this.forms.length && this.forms.forEach((form) => form.reset()),
              this.dispatchEvent(
                new CustomEvent("popupclosed", {
                  bubbles: !0,
                  composed: !0,
                  detail: { payload: payload || this.payload },
                })
              ),
              this.resolveClose(payload || this.payload),
              (this.isOpen = !1);
          }),
          popupStack.pop(),
          popupStack.items.length
            ? this.animateTo(
                popupStack.items[
                  popupStack.items.length - 1
                ].popup.shadowRoot.querySelector(".popup"),
                [
                  {
                    transform:
                      window.innerWidth > 640
                        ? "scale(0.95)"
                        : "translateY(-1.5rem)",
                  },
                  { transform: "none" },
                ],
                animOptions
              )
            : this.resumeScrolling(),
          this.resizeObserver.disconnect(),
          this.mutationObserver.disconnect(),
          this.removeEventListener("keydown", this.detectFocus),
          this.popupHeader.removeEventListener(
            "touchstart",
            this.handleTouchStart,
            { passive: !0 }
          ),
          this.backdrop.removeEventListener(
            "mousedown",
            this.handleSoftDismiss
          );
      };
      handleTouchStart = (e) => {
        (this.offset = 0),
          this.popupHeader.addEventListener("touchmove", this.handleTouchMove, {
            passive: !0,
          }),
          this.popupHeader.addEventListener("touchend", this.handleTouchEnd, {
            passive: !0,
          }),
          (this.touchStartY = e.changedTouches[0].clientY),
          (this.touchStartTime = e.timeStamp);
      };
      handleTouchMove = (e) => {
        this.touchStartY < e.changedTouches[0].clientY &&
          ((this.offset = e.changedTouches[0].clientY - this.touchStartY),
          (this.touchEndAnimation = window.requestAnimationFrame(() => {
            this.dialogBox.style.transform = `translateY(${this.offset}px)`;
          })));
      };
      handleTouchEnd = (e) => {
        if (
          ((this.touchEndTime = e.timeStamp),
          cancelAnimationFrame(this.touchEndAnimation),
          (this.touchEndY = e.changedTouches[0].clientY),
          (this.threshold =
            0.3 * this.dialogBox.getBoundingClientRect().height),
          this.touchEndTime - this.touchStartTime > 200)
        )
          if (this.touchEndY - this.touchStartY > this.threshold) {
            if (this.pinned) return void this.setStateOpen();
            this.hide();
          } else this.setStateOpen();
        else if (this.touchEndY > this.touchStartY) {
          if (this.pinned) return void this.setStateOpen();
          this.hide();
        }
        this.popupHeader.removeEventListener(
          "touchmove",
          this.handleTouchMove,
          { passive: !0 }
        ),
          this.popupHeader.removeEventListener(
            "touchend",
            this.handleTouchEnd,
            { passive: !0 }
          );
      };
      detectFocus = (e) => {
        if ("Tab" === e.key) {
          if (!this.focusable.length) return;
          if (!this.firstFocusable)
            for (let i = 0; i < this.focusable.length; i++)
              if (!this.focusable[i].disabled) {
                this.firstFocusable = this.focusable[i];
                break;
              }
          if (!this.lastFocusable)
            for (let i = this.focusable.length - 1; i >= 0; i--)
              if (!this.focusable[i].disabled) {
                this.lastFocusable = this.focusable[i];
                break;
              }
          e.shiftKey && document.activeElement === this.firstFocusable
            ? (e.preventDefault(),
              this.lastFocusable.tagName.includes("SM-")
                ? this.lastFocusable.focusIn()
                : this.lastFocusable.focus())
            : e.shiftKey ||
              document.activeElement !== this.lastFocusable ||
              (e.preventDefault(),
              this.firstFocusable.tagName.includes("SM-")
                ? this.firstFocusable.focusIn()
                : this.firstFocusable.focus());
        }
      };
      updateFocusableList = () => {
        (this.focusable = this.querySelectorAll(
          'sm-button:not([disabled]), button:not([disabled]), [href], sm-input, input:not([readonly]), sm-select, select, sm-checkbox, sm-textarea, textarea, [tabindex]:not([tabindex="-1"])'
        )),
          (this.autoFocus = this.querySelector("[autofocus]")),
          (this.firstFocusable = null),
          (this.lastFocusable = null);
      };
      handleSoftDismiss = () => {
        this.pinned
          ? this.dialogBox.animate(
              [
                { transform: "translateX(-1rem)" },
                { transform: "translateX(1rem)" },
                { transform: "translateX(-0.5rem)" },
                { transform: "translateX(0.5rem)" },
                { transform: "translateX(0)" },
              ],
              { duration: 300, easing: "ease" }
            )
          : this.hide();
      };
      debounce = (callback, wait) => {
        let timeoutId = null;
        return (...args) => {
          window.clearTimeout(timeoutId),
            (timeoutId = window.setTimeout(() => {
              callback.apply(null, args);
            }, wait));
        };
      };
      connectedCallback() {
        this.popupBodySlot.addEventListener(
          "slotchange",
          this.debounce(() => {
            (this.forms = this.querySelectorAll("sm-form")),
              this.updateFocusableList();
          }, 0)
        ),
          (this.resizeObserver = new ResizeObserver((entries) => {
            entries.forEach((entry) => {
              if (entry.contentBoxSize) {
                const contentBoxSize = Array.isArray(entry.contentBoxSize)
                  ? entry.contentBoxSize[0]
                  : entry.contentBoxSize;
                this.threshold = 0.3 * contentBoxSize.blockSize.height;
              } else this.threshold = 0.3 * entry.contentRect.height;
            });
          })),
          (this.mutationObserver = new MutationObserver((entries) => {
            this.updateFocusableList();
          }));
      }
      disconnectedCallback() {
        this.resizeObserver.disconnect(),
          this.mutationObserver.disconnect(),
          this.removeEventListener("keydown", this.detectFocus),
          this.popupHeader.removeEventListener(
            "touchstart",
            this.handleTouchStart,
            { passive: !0 }
          ),
          this.backdrop.removeEventListener(
            "mousedown",
            this.handleSoftDismiss
          );
      }
      attributeChangedCallback(name) {
        "open" === name && this.hasAttribute("open") && this.show();
      }
    }
  );
const spinner = document.createElement("template");
spinner.innerHTML =
  '<style> *{ padding: 0; margin: 0; -webkit-box-sizing: border-box; box-sizing: border-box;}.loader { display: flex; height: var(--size, 1.5rem); width: var(--size, 1.5rem); stroke-width: 8; overflow: visible; stroke: var(--accent-color, teal); fill: none; stroke-dashoffset: 180; stroke-dasharray: 180; animation: load 2s infinite, spin 1s linear infinite;}@keyframes load { 50% { stroke-dashoffset: 0; } 100%{ stroke-dashoffset: -180; }}@keyframes spin { 100% { transform: rotate(360deg); }}</style><svg viewBox="0 0 64 64" class="loader"><circle cx="32" cy="32" r="32" /></svg>';
class SpinnerLoader extends HTMLElement {
  constructor() {
    super(),
      this.attachShadow({ mode: "open" }).append(spinner.content.cloneNode(!0));
  }
}
window.customElements.define("sm-spinner", SpinnerLoader);
const themeToggle = document.createElement("template");
themeToggle.innerHTML =
  ' <style> *{ padding: 0; margin: 0; box-sizing: border-box; } :host{ cursor: pointer; --height: 2.5rem; --width: 2.5rem; } .theme-toggle { display: flex; position: relative; width: 1.2rem; height: 1.2rem; cursor: pointer; -webkit-tap-highlight-color: transparent; } .theme-toggle::after{ content: \'\'; position: absolute; height: var(--height); width: var(--width); top: 50%; left: 50%; opacity: 0; border-radius: 50%; pointer-events: none; transition: transform 0.3s, opacity 0.3s; transform: translate(-50%, -50%) scale(1.2); background-color: rgba(var(--text-color,inherit), 0.12); } :host(:focus-within) .theme-toggle{ outline: none; } :host(:focus-within) .theme-toggle::after{ opacity: 1; transform: translate(-50%, -50%) scale(1); } .icon { position: absolute; height: 100%; width: 100%; fill: rgba(var(--text-color,inherit), 1); transition: transform 0.3s, opacity 0.1s; }  .theme-switcher__checkbox { display: none; } :host([checked]) .moon-icon { transform: translateY(50%); opacity: 0; } :host(:not([checked])) .sun-icon { transform: translateY(50%); opacity: 0; } </style> <label class="theme-toggle" title="Change theme" tabindex="0"> <slot name="light-mode-icon"> <svg xmlns="http://www.w3.org/2000/svg" class="icon moon-icon" enable-background="new 0 0 24 24" height="24px" viewBox="0 0 24 24" width="24px" fill="#000000"><rect fill="none" height="24" width="24"/><path d="M9.37,5.51C9.19,6.15,9.1,6.82,9.1,7.5c0,4.08,3.32,7.4,7.4,7.4c0.68,0,1.35-0.09,1.99-0.27C17.45,17.19,14.93,19,12,19 c-3.86,0-7-3.14-7-7C5,9.07,6.81,6.55,9.37,5.51z M12,3c-4.97,0-9,4.03-9,9s4.03,9,9,9s9-4.03,9-9c0-0.46-0.04-0.92-0.1-1.36 c-0.98,1.37-2.58,2.26-4.4,2.26c-2.98,0-5.4-2.42-5.4-5.4c0-1.81,0.89-3.42,2.26-4.4C12.92,3.04,12.46,3,12,3L12,3z"/></svg> </slot> <slot name="dark-mode-icon"> <svg xmlns="http://www.w3.org/2000/svg" class="icon sun-icon" enable-background="new 0 0 24 24" height="24px" viewBox="0 0 24 24" width="24px" fill="#000000"><rect fill="none" height="24" width="24"/><path d="M12,9c1.65,0,3,1.35,3,3s-1.35,3-3,3s-3-1.35-3-3S10.35,9,12,9 M12,7c-2.76,0-5,2.24-5,5s2.24,5,5,5s5-2.24,5-5 S14.76,7,12,7L12,7z M2,13l2,0c0.55,0,1-0.45,1-1s-0.45-1-1-1l-2,0c-0.55,0-1,0.45-1,1S1.45,13,2,13z M20,13l2,0c0.55,0,1-0.45,1-1 s-0.45-1-1-1l-2,0c-0.55,0-1,0.45-1,1S19.45,13,20,13z M11,2v2c0,0.55,0.45,1,1,1s1-0.45,1-1V2c0-0.55-0.45-1-1-1S11,1.45,11,2z M11,20v2c0,0.55,0.45,1,1,1s1-0.45,1-1v-2c0-0.55-0.45-1-1-1C11.45,19,11,19.45,11,20z M5.99,4.58c-0.39-0.39-1.03-0.39-1.41,0 c-0.39,0.39-0.39,1.03,0,1.41l1.06,1.06c0.39,0.39,1.03,0.39,1.41,0s0.39-1.03,0-1.41L5.99,4.58z M18.36,16.95 c-0.39-0.39-1.03-0.39-1.41,0c-0.39,0.39-0.39,1.03,0,1.41l1.06,1.06c0.39,0.39,1.03,0.39,1.41,0c0.39-0.39,0.39-1.03,0-1.41 L18.36,16.95z M19.42,5.99c0.39-0.39,0.39-1.03,0-1.41c-0.39-0.39-1.03-0.39-1.41,0l-1.06,1.06c-0.39,0.39-0.39,1.03,0,1.41 s1.03,0.39,1.41,0L19.42,5.99z M7.05,18.36c0.39-0.39,0.39-1.03,0-1.41c-0.39-0.39-1.03-0.39-1.41,0l-1.06,1.06 c-0.39,0.39-0.39,1.03,0,1.41s1.03,0.39,1.41,0L7.05,18.36z"/></svg> </slot> </label>';
class ThemeToggle extends HTMLElement {
  constructor() {
    super(),
      this.attachShadow({ mode: "open" }).append(
        themeToggle.content.cloneNode(!0)
      ),
      (this.isChecked = !1),
      (this.hasTheme = "light"),
      (this.toggleState = this.toggleState.bind(this)),
      (this.fireEvent = this.fireEvent.bind(this)),
      (this.handleThemeChange = this.handleThemeChange.bind(this));
  }
  static get observedAttributes() {
    return ["checked"];
  }
  daylight() {
    (this.hasTheme = "light"),
      (document.body.dataset.theme = "light"),
      this.setAttribute("aria-checked", "false");
  }
  nightlight() {
    (this.hasTheme = "dark"),
      (document.body.dataset.theme = "dark"),
      this.setAttribute("aria-checked", "true");
  }
  toggleState() {
    if (!document.startViewTransition)
      return this.toggleAttribute("checked"), void this.fireEvent();
    document.startViewTransition(() => {
      this.toggleAttribute("checked"), this.fireEvent();
    });
  }
  handleKeyDown(e) {
    " " === e.key && this.toggleState();
  }
  handleThemeChange(e) {
    e.detail.theme !== this.hasTheme &&
      ("dark" === e.detail.theme
        ? this.setAttribute("checked", "")
        : this.removeAttribute("checked"));
  }
  fireEvent() {
    this.dispatchEvent(
      new CustomEvent("themechange", {
        bubbles: !0,
        composed: !0,
        detail: { theme: this.hasTheme },
      })
    );
  }
  connectedCallback() {
    this.setAttribute("role", "switch"),
      this.setAttribute("aria-label", "theme toggle"),
      "dark" === localStorage.getItem(`${window.location.hostname}-theme`)
        ? (this.nightlight(), this.setAttribute("checked", ""))
        : "light" === localStorage.getItem(`${window.location.hostname}-theme`)
        ? (this.daylight(), this.removeAttribute("checked"))
        : window.matchMedia("(prefers-color-scheme: dark)").matches
        ? (this.nightlight(), this.setAttribute("checked", ""))
        : (this.daylight(), this.removeAttribute("checked")),
      this.addEventListener("click", this.toggleState),
      this.addEventListener("keydown", this.handleKeyDown),
      document.addEventListener("themechange", this.handleThemeChange);
  }
  disconnectedCallback() {
    this.removeEventListener("click", this.toggleState),
      this.removeEventListener("keydown", this.handleKeyDown),
      document.removeEventListener("themechange", this.handleThemeChange);
  }
  attributeChangedCallback(e, t, n) {
    "checked" === e &&
      (this.hasAttribute("checked")
        ? (this.nightlight(),
          localStorage.setItem(`${window.location.hostname}-theme`, "dark"))
        : (this.daylight(),
          localStorage.setItem(`${window.location.hostname}-theme`, "light")));
  }
}
window.customElements.define("theme-toggle", ThemeToggle);
