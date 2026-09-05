(() => {
  const escapeHtml = (value) => String(value ?? '').replace(/[&<>'"]/g, (char) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;'
  })[char]);

  function bindConfirm(root = document) {
    root.querySelectorAll('[data-confirm]:not([data-confirm-bound])').forEach((element) => {
      element.dataset.confirmBound = '1';
      element.addEventListener('click', (event) => {
        if (!window.confirm(element.dataset.confirm || 'Подтвердить действие?')) {
          event.preventDefault();
        }
      });
    });
  }
  bindConfirm();

  const registrationSubmit = document.querySelector('[data-registration-submit]');
  if (registrationSubmit) {
    const password = document.querySelector('input[name="password"]');
    const repeat = document.querySelector('input[name="password_repeat"]');
    const rules = document.querySelector('[data-password-rules]');
    const match = document.querySelector('[data-password-match]');
    const validateRegistrationPassword = () => {
      const value = password.value;
      const checks = {
        length: value.length >= 8,
        lower: /[a-zа-яё]/iu.test(value),
        upper: /[A-ZА-ЯЁ]/u.test(value),
        digit: /\d/.test(value)
      };
      Object.entries(checks).forEach(([name, valid]) => rules.querySelector(`[data-rule="${name}"]`).classList.toggle('valid', valid));
      const matches = value !== '' && value === repeat.value;
      match.classList.toggle('valid', matches);
      match.textContent = matches ? 'Пароли совпадают.' : 'Пароли должны совпадать.';
      registrationSubmit.disabled = !Object.values(checks).every(Boolean) || !matches;
    };
    password.addEventListener('input', validateRegistrationPassword);
    repeat.addEventListener('input', validateRegistrationPassword);
    validateRegistrationPassword();
  }

  const shipmentTypeInputs = document.querySelectorAll('input[name="cargo_modes[]"]');
  const standardOnly = document.querySelector('[data-standard-only]');
  if (shipmentTypeInputs.length && standardOnly) {
    const syncShipmentFields = () => {
      const enabled = [...shipmentTypeInputs].some((input) => input.checked && input.value === 'standard');
      standardOnly.hidden = !enabled;
      standardOnly.querySelectorAll('input').forEach((input) => { input.disabled = !enabled; });
    };
    shipmentTypeInputs.forEach((input) => input.addEventListener('change', syncShipmentFields));
    syncShipmentFields();
  }

  const oversizedFields = document.querySelector('[data-oversized-fields]');
  const standardFields = document.querySelector('[data-standard-fields]');
  if (shipmentTypeInputs.length) {
    const syncCargoSections = () => shipmentTypeInputs.forEach((toggle) => {
      const section = toggle.value === 'standard' ? standardFields : oversizedFields;
      if (!section) return;
      section.hidden = !toggle.checked;
      section.querySelectorAll('textarea').forEach((field) => { field.disabled = !toggle.checked; field.required = toggle.checked; });
    });
    shipmentTypeInputs.forEach((input) => input.addEventListener('change', syncCargoSections));
    syncCargoSections();
    const orderForm = shipmentTypeInputs[0].form;
    if (orderForm) orderForm.addEventListener('submit', (event) => {
      if (![...shipmentTypeInputs].some((input) => input.checked)) {
        event.preventDefault();
        shipmentTypeInputs[0].focus();
      }
    });
  }

  const routeMap = document.querySelector('[data-route-map]');
  if (routeMap) {
    const pickup = document.querySelector('[name="pickup_location_id"]');
    const destination = document.querySelector('[name="destination_location_id"]');
    const syncMap = () => routeMap.querySelectorAll('.map-location').forEach((pin) => {
      pin.classList.toggle('pickup', pickup && pickup.value === pin.dataset.locationId);
      pin.classList.toggle('destination', destination && destination.value === pin.dataset.locationId);
    });
    if (pickup) pickup.addEventListener('change', syncMap);
    if (destination) destination.addEventListener('change', syncMap);
    syncMap();
  }

  const missionRoot = document.querySelector('[data-mission-poll]');
  if (missionRoot) {
    const endpoint = missionRoot.dataset.missionPoll;
    const missionId = missionRoot.dataset.missionId;
    const csrf = missionRoot.dataset.csrf;
    const statusElement = document.querySelector('[data-mission-status]');
    const updatedElement = document.querySelector('[data-mission-updated]');
    const eventList = document.querySelector('[data-event-list]');
    const actions = document.querySelector('[data-mission-actions]');

    function renderActions(data) {
      if (!actions) return;
      const forms = [];
      if ((data.allowed_actions || []).includes('confirm_loaded')) {
        forms.push(`<form method="post" action="${location.origin}${location.pathname}/confirm-loaded"><input type="hidden" name="csrf" value="${escapeHtml(csrf)}"><input type="hidden" name="version" value="${Number(data.version)}"><button class="button primary" type="submit">Погрузка завершена — старт</button></form>`);
      }
      if ((data.allowed_actions || []).includes('cancel')) {
        forms.push(`<form method="post" action="${location.origin}${location.pathname}/cancel"><input type="hidden" name="csrf" value="${escapeHtml(csrf)}"><input type="hidden" name="version" value="${Number(data.version)}"><button class="button danger" data-confirm="Отменить заказ?" type="submit">Отменить</button></form>`);
      }
      actions.innerHTML = forms.join('');
      bindConfirm(actions);
    }

    async function refreshMission() {
      try {
        const response = await fetch(endpoint, { headers: { Accept: 'application/json' }, cache: 'no-store', credentials: 'same-origin' });
        if (response.status === 401 || response.status === 403) {
          location.reload();
          return;
        }
        if (!response.ok) return;
        const data = await response.json();
        if (statusElement) {
          statusElement.textContent = data.status_label;
          statusElement.className = data.status_class;
        }
        if (updatedElement) updatedElement.textContent = data.updated_at;
        renderActions(data);
        if (eventList && Array.isArray(data.events)) {
          eventList.innerHTML = data.events.map((event) => `<li><span class="event-dot"></span><div><strong>${escapeHtml(event.label)}</strong><small>${escapeHtml(event.source)} · ${escapeHtml(event.occurred_at)}</small></div></li>`).join('');
        }
      } catch (_) {
        // Последнее известное состояние остаётся на экране.
      }
    }
    window.setInterval(refreshMission, 2000);
  }

  const revisionRoot = document.querySelector('[data-revision-scope]');
  if (revisionRoot && !missionRoot) {
    const scope = revisionRoot.dataset.revisionScope;
    let revision = revisionRoot.dataset.revision;
    async function checkRevision() {
      if (document.hidden) return;
      const active = document.activeElement;
      if (active && ['INPUT', 'TEXTAREA', 'SELECT'].includes(active.tagName)) return;
      try {
        const response = await fetch(`/api/revision?scope=${encodeURIComponent(scope)}`, { cache: 'no-store', credentials: 'same-origin' });
        if (!response.ok) return;
        const data = await response.json();
        if (revision && data.revision && data.revision !== revision) {
          location.reload();
          return;
        }
        revision = data.revision;
      } catch (_) {}
    }
    window.setInterval(checkRevision, 3000);
  }
})();
