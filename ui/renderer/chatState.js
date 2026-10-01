/** Per-case chat history — survives sidebar navigation (window-backed singleton). */

function chatStore() {
  if (typeof window !== 'undefined') {
    if (!window.__forensicChatByCase) {
      window.__forensicChatByCase = Object.create(null);
    }
    return window.__forensicChatByCase;
  }
  if (!chatStore._fallback) {
    chatStore._fallback = Object.create(null);
  }
  return chatStore._fallback;
}

export function getChatMessages(caseId) {
  if (!caseId) return [];
  const store = chatStore();
  if (!store[caseId]) {
    store[caseId] = [];
  }
  return store[caseId];
}
