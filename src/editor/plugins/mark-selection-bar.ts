import { $prose } from '@milkdown/kit/utils';
import { Plugin, PluginKey } from '@milkdown/kit/prose/state';
import type { EditorView } from '@milkdown/kit/prose/view';

import { flag, suggestReplace } from './marks';
import type { MarkRange } from './marks';
import { openCommentComposer } from './mark-popover';
import { getCurrentActor } from '../actor';
import { shouldKeepCollapsedSelectionBarVisible } from './selection-bar-visibility';
import { isMobileTouch } from './mobile-detect';
import { shouldUseCommentUiV2 } from './comment-ui-mode';
import { canCommentInRuntime } from './share-permissions';

const markSelectionBarKey = new PluginKey('mark-selection-bar');
const CACHED_RANGE_TTL_MS = 12_000;
const BAR_INTERACTION_GRACE_MS = 250;

function getSelectionRange(view: EditorView): MarkRange | null {
  const { from, to } = view.state.selection;
  if (from === to) return null;
  return { from, to };
}

function quoteForRange(view: EditorView, range: MarkRange): string {
  return view.state.doc.textBetween(range.from, range.to, '\n', '\n');
}

function clamp(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(value, max));
}

const TOP_FIXED_OVERLAY_IDS = ['share-banner', 'readonly-banner', 'review-lock-banner', 'error-banner'] as const;

function getTopViewportInset(margin: number): number {
  let inset = margin;
  for (const id of TOP_FIXED_OVERLAY_IDS) {
    const element = document.getElementById(id);
    if (!element) continue;
    const style = window.getComputedStyle(element);
    if (style.position !== 'fixed' && style.position !== 'sticky') continue;
    if (typeof element.getBoundingClientRect !== 'function') continue;
    const rect = element.getBoundingClientRect();
    if (rect.height <= 0 || rect.bottom <= 0) continue;
    inset = Math.max(inset, Math.ceil(rect.bottom + margin));
  }
  return inset;
}

function getAnchorBox(view: EditorView, range: MarkRange) {
  const from = view.coordsAtPos(range.from);
  const to = view.coordsAtPos(range.to);
  return {
    top: Math.min(from.top, to.top),
    bottom: Math.max(from.bottom, to.bottom),
    left: Math.min(from.left, to.left),
    right: Math.max(from.right, to.right)
  };
}

function positionBar(bar: HTMLElement, view: EditorView, range: MarkRange): void {
  try {
    // --- DOM reads (batched) ---
    const anchorBox = getAnchorBox(view, range);
    if (typeof view.dom.getBoundingClientRect !== 'function') return;
    if (typeof bar.getBoundingClientRect !== 'function') return;
    const editorRect = view.dom.getBoundingClientRect();
    const barRect = bar.getBoundingClientRect();
    const margin = 12;
    const dockGap = 16;
    const viewportW = window.innerWidth;
    const viewportH = window.innerHeight;
    const safeTop = getTopViewportInset(margin);

    // --- DOM writes (all reads complete above) ---
    const barW = barRect.width;
    const barH = barRect.height;
    const maxTop = Math.max(safeTop, viewportH - barH - margin);
    const spaceRight = viewportW - editorRect.right;
    const spaceLeft = editorRect.left;
    const canDockRight = spaceRight >= barW + dockGap;
    const canDockLeft = spaceLeft >= barW + dockGap;

    let left: number;
    let top: number;

    if (canDockRight || canDockLeft) {
      const dockRight = canDockRight || !canDockLeft;
      left = dockRight
        ? clamp(editorRect.right + dockGap, margin, viewportW - barW - margin)
        : clamp(editorRect.left - dockGap - barW, margin, viewportW - barW - margin);
      top = clamp(anchorBox.top - 6, safeTop, maxTop);
    } else {
      const aboveTop = anchorBox.top - barH - margin;
      const belowTop = anchorBox.bottom + margin;
      const hasRoomAbove = aboveTop >= safeTop;
      const hasRoomBelow = belowTop + barH <= viewportH - margin;
      top = hasRoomAbove
        ? aboveTop
        : (hasRoomBelow
          ? belowTop
          : clamp(anchorBox.top, safeTop, maxTop));
      const center = (anchorBox.left + anchorBox.right) / 2;
      left = clamp(center - barW / 2, margin, viewportW - barW - margin);
    }

    bar.style.left = `${left}px`;
    bar.style.top = `${top}px`;
  } catch {
    // Ignore positioning errors for invalid positions.
  }
}

function isRangeValid(view: EditorView, range: MarkRange | null): range is MarkRange {
  if (!range) return false;
  return range.from >= 0 && range.to > range.from && range.to <= view.state.doc.content.size;
}

class MarkSelectionBarController {
  private view: EditorView;
  private bar: HTMLDivElement;
  private hintEl: HTMLDivElement;
  private lastRange: MarkRange | null = null;
  private cachedRange: MarkRange | null = null;
  private cachedAt = 0;
  private preserveCollapsedUntil = 0;
  private hintTimer: number | null = null;

  private handleScroll = () => {
    if (this.lastRange) {
      positionBar(this.bar, this.view, this.lastRange);
    }
  };

  private handleSelectionChange = () => {
    this.cacheLiveSelection();
  };

  private handlePointerUp = () => {
    this.cacheLiveSelection();
  };

  private handleKeyUp = () => {
    this.cacheLiveSelection();
  };

  constructor(view: EditorView) {
    this.view = view;
    this.bar = document.createElement('div');
    this.bar.className = 'mark-selection-bar';
    this.bar.style.display = 'none';
    this.bar.addEventListener('pointerdown', event => {
      this.preserveBarDuringInteraction();
      const range = getSelectionRange(this.view);
      if (range) {
        this.rememberRange(range);
      }
      event.preventDefault();
      event.stopPropagation();
    });
    this.bar.addEventListener('touchend', () => {
      const range = getSelectionRange(this.view);
      if (range) {
        this.rememberRange(range);
      }
    });

    this.hintEl = document.createElement('div');
    this.hintEl.className = 'mark-selection-bar-hint';
    this.hintEl.style.display = 'none';

    const container = view.dom.parentElement ?? document.body;
    container.appendChild(this.bar);
    container.appendChild(this.hintEl);

    this.buildButtons();

    document.addEventListener('selectionchange', this.handleSelectionChange);
    view.dom.addEventListener('pointerup', this.handlePointerUp);
    view.dom.addEventListener('keyup', this.handleKeyUp);
    window.addEventListener('scroll', this.handleScroll, { passive: true });
    window.addEventListener('resize', this.handleScroll, { passive: true });
  }

  destroy(): void {
    document.removeEventListener('selectionchange', this.handleSelectionChange);
    this.view.dom.removeEventListener('pointerup', this.handlePointerUp);
    this.view.dom.removeEventListener('keyup', this.handleKeyUp);
    window.removeEventListener('scroll', this.handleScroll);
    window.removeEventListener('resize', this.handleScroll);
    if (this.hintTimer !== null) {
      window.clearTimeout(this.hintTimer);
      this.hintTimer = null;
    }
    this.hintEl.remove();
    this.bar.remove();
  }

  update(view: EditorView): void {
    this.view = view;
    if (!canCommentInRuntime()) {
      this.bar.style.display = 'none';
      this.hintEl.style.display = 'none';
      return;
    }
    if (isMobileTouch() && shouldUseCommentUiV2()) {
      this.bar.style.display = 'none';
      this.hintEl.style.display = 'none';
      return;
    }
    const range = getSelectionRange(view);
    if (!range) {
      const cachedRange = this.getCachedRange();
      if (
        shouldKeepCollapsedSelectionBarVisible({
          hasCachedRange: Boolean(cachedRange),
          hasLastRange: Boolean(this.lastRange),
          preserveCollapsedVisibility: this.shouldPreserveCollapsedVisibility()
        }) && this.lastRange
      ) {
        if (isRangeValid(view, this.lastRange)) {
          this.rememberRange(this.lastRange);
        }
        this.bar.style.display = 'flex';
        positionBar(this.bar, view, this.lastRange);
        return;
      }
      this.lastRange = null;
      this.bar.style.display = 'none';
      return;
    }

    this.rememberRange(range);
    this.bar.style.display = 'flex';
    positionBar(this.bar, view, range);
  }

  private cacheLiveSelection(): void {
    const range = getSelectionRange(this.view);
    if (!range) return;
    this.rememberRange(range);
  }

  private rememberRange(range: MarkRange): void {
    this.lastRange = range;
    this.cachedRange = range;
    this.cachedAt = Date.now();
  }

  private preserveBarDuringInteraction(): void {
    this.preserveCollapsedUntil = Date.now() + BAR_INTERACTION_GRACE_MS;
  }

  private shouldPreserveCollapsedVisibility(): boolean {
    return Date.now() <= this.preserveCollapsedUntil;
  }

  private getCachedRange(): MarkRange | null {
    if (!this.cachedRange) return null;
    if ((Date.now() - this.cachedAt) > CACHED_RANGE_TTL_MS) {
      this.cachedRange = null;
      this.cachedAt = 0;
      return null;
    }
    if (!isRangeValid(this.view, this.cachedRange)) {
      this.cachedRange = null;
      this.cachedAt = 0;
      return null;
    }
    return this.cachedRange;
  }

  private getActionRange(): MarkRange | null {
    const live = getSelectionRange(this.view);
    if (isRangeValid(this.view, live)) {
      this.rememberRange(live);
      return live;
    }

    const cached = this.getCachedRange();
    if (cached) return cached;

    if (isRangeValid(this.view, this.lastRange)) return this.lastRange;

    this.showHint('Select text first');
    return null;
  }

  private showHint(message: string): void {
    this.hintEl.textContent = message;
    this.hintEl.style.display = 'block';
    if (this.lastRange) {
      positionBar(this.hintEl, this.view, this.lastRange);
      this.hintEl.style.top = `${parseFloat(this.hintEl.style.top || '0') + 44}px`;
    }
    if (this.hintTimer !== null) {
      window.clearTimeout(this.hintTimer);
    }
    this.hintTimer = window.setTimeout(() => {
      this.hintEl.style.display = 'none';
      this.hintTimer = null;
    }, 1200);
  }

  private buildButtons(): void {
    this.bar.innerHTML = '';

    const makeButton = (label: string, onClick: () => void) => {
      const button = document.createElement('button');
      button.type = 'button';
      button.textContent = label;
      button.addEventListener('pointerdown', (event) => {
        this.preserveBarDuringInteraction();
        event.preventDefault();
        event.stopPropagation();
      });
      button.addEventListener('click', () => {
        onClick();
      });
      return button;
    };

    const commentButton = makeButton('Comment', () => {
      if (!canCommentInRuntime()) return;
      const range = this.getActionRange();
      if (!range) return;
      openCommentComposer(this.view, range, getCurrentActor());
    });

    const flagButton = makeButton('Flag', () => {
      if (!canCommentInRuntime()) return;
      const range = this.getActionRange();
      if (!range) return;
      const quote = quoteForRange(this.view, range);
      flag(this.view, quote, getCurrentActor(), undefined, range);
    });

    const suggestButton = makeButton('Suggest', () => {
      if (!canCommentInRuntime()) return;
      const range = this.getActionRange();
      if (!range) return;
      const original = this.view.state.doc.textBetween(range.from, range.to, '\n', '\n');
      const replacement = window.prompt('Suggest replacement', original);
      if (replacement === null || replacement === original) return;
      const quote = quoteForRange(this.view, range);
      suggestReplace(this.view, quote, getCurrentActor(), replacement, range);
    });

    this.bar.appendChild(commentButton);
    this.bar.appendChild(flagButton);
    this.bar.appendChild(suggestButton);
  }
}

export const markSelectionBarPlugin = $prose(() => {
  return new Plugin({
    key: markSelectionBarKey,
    view(view) {
      return new MarkSelectionBarController(view);
    }
  });
});
