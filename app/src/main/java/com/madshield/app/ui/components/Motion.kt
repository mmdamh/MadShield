package com.madshield.app.ui.components

import android.view.HapticFeedbackConstants
import androidx.compose.animation.EnterTransition
import androidx.compose.animation.ExitTransition
import androidx.compose.animation.core.CubicBezierEasing
import androidx.compose.animation.core.tween
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.slideOutHorizontally
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.platform.LocalView

/**
 * The app's motion vocabulary in one place, so every screen moves the same way.
 *
 * Durations and curves are Material 3's motion tokens (medium2 = 300 ms for things that arrive, short4 = 200 ms for
 * things that leave; emphasized-decelerate in, emphasized-accelerate out). Moves are short on purpose: a page slides
 * about an eighth of the screen while it fades, it does not travel the whole width.
 *
 * Direction: [dir] is +1 when the new content should come from the reading-end side. In a right-to-left language
 * (Persian) the reading end is the left, so callers pass -1 there and the slide mirrors with the layout.
 */
object Motion {
    const val ENTER_MS = 300
    const val EXIT_MS = 200

    val Decelerate = CubicBezierEasing(0.05f, 0.7f, 0.1f, 1f)
    val Accelerate = CubicBezierEasing(0.3f, 0f, 0.8f, 0.15f)

    /** A new page arriving (forward navigation, or a tab further along the bar). */
    fun arrive(dir: Int): EnterTransition =
        slideInHorizontally(tween(ENTER_MS, easing = Decelerate)) { dir * it / 8 } +
            fadeIn(tween(ENTER_MS - 80, delayMillis = 80, easing = Decelerate))

    /** The page that is covered: a smaller move the other way, gone before the new one has settled. */
    fun cover(dir: Int): ExitTransition =
        slideOutHorizontally(tween(EXIT_MS, easing = Accelerate)) { -dir * it / 10 } +
            fadeOut(tween(EXIT_MS - 50, easing = Accelerate))

    /** Show/hide of a block that grows in place (help text, a folded card's body). */
    val reveal: EnterTransition =
        fadeIn(tween(ENTER_MS - 60, delayMillis = 60, easing = Decelerate)) +
            expandVertically(tween(ENTER_MS, easing = Decelerate), expandFrom = Alignment.Top)

    val conceal: ExitTransition =
        fadeOut(tween(EXIT_MS - 50, easing = Accelerate)) +
            shrinkVertically(tween(EXIT_MS, easing = Accelerate), shrinkTowards = Alignment.Top)
}

/**
 * A light tick for a selection change. It goes through the view, so the system's "touch feedback" setting decides
 * whether the phone vibrates at all; the app never overrides that.
 */
@Composable
fun rememberTick(): () -> Unit {
    val view = LocalView.current
    return remember(view) { { view.performHapticFeedback(HapticFeedbackConstants.CLOCK_TICK) } }
}
