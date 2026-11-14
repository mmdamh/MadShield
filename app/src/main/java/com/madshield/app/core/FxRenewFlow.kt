package com.madshield.app.core

/**
 * What the renewal dialog shows (MadShield: the Fastly CAPTCHA renewal, patch 0003). One value per step a person can see.
 * Nothing in here says an answer was "wrong": the core never knows that, so neither does the app. [Failed] carries the
 * core's fixed failure word ([FxReauthCodes.failures]) or one of the app's own ([FxRenewFlow] constants).
 */
sealed class FxRenewUi {
    /** Asking the core to start, or waiting for Mozilla to answer before a picture is ready. */
    object Connecting : FxRenewUi()

    /** A picture waits. [another] is true for a picture that followed an answer; [notice] a failed send to show next to it. */
    data class Captcha(val id: String, val image: String, val round: Int, val another: Boolean, val cause: String, val notice: String = "") : FxRenewUi()

    /** The answer is on its way to the core, or the core is sending it to Fastly. */
    object Submitting : FxRenewUi()

    /** Fastly has the answer; the core is checking it and renewing the token. */
    object Verifying : FxRenewUi()

    data class Success(val renewed: Boolean) : FxRenewUi()
    data class Failed(val code: String, val detail: String) : FxRenewUi()
    object Cancelled : FxRenewUi()
    object TimedOut : FxRenewUi()

    val isFinal: Boolean get() = this is Success || this is Failed || this is Cancelled || this is TimedOut
}

/**
 * The logic of one renewal as the app sees it, without any screen in it (so it is tested in the pure tests): which view of
 * the core belongs to this renewal, what the dialog shows for it, and the guard that lets one answer go out per picture.
 *
 * One instance is one operation ([op], named by the core). It is used from one thread (the dialog's). Rules:
 *  - a view naming another operation (or none) ends this one as lost: a newer renewal owns the core now;
 *  - once the dialog shows a final step it never changes again;
 *  - [beginSubmit] accepts one answer for the picture shown; a second tap, or a tap on a picture that was replaced, is refused;
 *  - while an answer for picture X is out, a view that still shows X (the core had not moved on when it was read) does not
 *    bring the answer field back, so polling cannot race with the submission;
 *  - a send that failed without reaching the core's logic ([submitFailed]) gives the same picture back, with the reason.
 */
class FxRenewFlow {
    var op: String = ""
        private set
    var ui: FxRenewUi = FxRenewUi.Connecting
        private set

    private var shown: FxRenewUi.Captcha? = null
    private var submittedId: String = ""
    private var pollFailures = 0

    /** The core accepted the start (or joined the renewal already running for this account). */
    fun started(view: FxReauth): FxRenewUi {
        if (view.op.isEmpty()) return end(FxRenewUi.Failed(LOST, ""))
        op = view.op
        return apply(view)
    }

    /** The start request itself failed: [code] is [ApiException.code] of the core's refusal, "" for a request that did not get through. */
    fun startFailed(code: String, message: String): FxRenewUi =
        end(if (code == FxReauthCodes.BUSY) FxRenewUi.Failed(FxReauthCodes.BUSY, "") else FxRenewUi.Failed(REQUEST, message))

    /** A view read from the core. Returns what to show. */
    fun apply(view: FxReauth): FxRenewUi {
        if (ui.isFinal) return ui
        pollFailures = 0
        if (op.isEmpty() || view.op != op) {
            return end(FxRenewUi.Failed(if (view.op.isEmpty()) LOST else SUPERSEDED, ""))
        }
        val next: FxRenewUi = when (view.state) {
            FxReauthState.WAITING, FxReauthState.ADDITIONAL -> {
                if (!view.waitingCaptcha) FxRenewUi.Connecting
                else if (view.id == submittedId) FxRenewUi.Submitting // the answer for this picture is out: not asked again
                else FxRenewUi.Captcha(
                    view.id, view.image, view.round, view.state == FxReauthState.ADDITIONAL, view.cause,
                    notice = shown?.takeIf { it.id == view.id }?.notice.orEmpty() // a failed send stays visible while the same picture waits
                ).also { shown = it }
            }
            FxReauthState.SUBMITTING -> FxRenewUi.Submitting
            FxReauthState.VERIFYING -> FxRenewUi.Verifying
            FxReauthState.COMPLETED -> FxRenewUi.Success(view.renewed)
            FxReauthState.FAILED -> FxRenewUi.Failed(view.code.ifEmpty { "challenge_failed" }, view.error)
            FxReauthState.CANCELLED -> FxRenewUi.Cancelled
            FxReauthState.TIMED_OUT -> FxRenewUi.TimedOut
            else -> FxRenewUi.Connecting // starting (or a word this app does not know yet)
        }
        ui = next
        return next
    }

    /**
     * A read of the core failed. One failure is not the end (the core may be busy answering Fastly); [MAX_POLL_FAILURES] in
     * a row are. Returns what to show.
     */
    fun pollFailed(message: String): FxRenewUi {
        if (ui.isFinal) return ui
        pollFailures++
        return if (pollFailures >= MAX_POLL_FAILURES) end(FxRenewUi.Failed(REQUEST, message)) else ui
    }

    /**
     * The person tapped Send for picture [id]. True when the answer may go out: that picture is the one shown, no answer was
     * sent for it, and there is something to send. The dialog then shows [FxRenewUi.Submitting] and sends the answer.
     */
    fun beginSubmit(id: String, answer: String): Boolean {
        val cur = ui as? FxRenewUi.Captcha ?: return false
        if (cur.id != id || id == submittedId || answer.isBlank()) return false
        submittedId = id
        ui = FxRenewUi.Submitting
        return true
    }

    /**
     * Sending the answer for picture [id] failed: [code] is the core's refusal word, "" when the request did not get through.
     * A refusal that says the picture or the operation is no longer current changes nothing here (the next view says what
     * happened). Any other failure puts the same picture back, with the reason, so the person can send again.
     */
    fun submitFailed(id: String, code: String, message: String): FxRenewUi {
        if (ui.isFinal || id != submittedId) return ui
        when (code) {
            FxReauthCodes.STALE_CHALLENGE, FxReauthCodes.ALREADY_SUBMITTED, FxReauthCodes.STALE_OPERATION, FxReauthCodes.NO_CHALLENGE -> return ui
        }
        val pic = shown
        if (pic == null || pic.id != id) return ui
        submittedId = ""
        val back = pic.copy(notice = message.ifEmpty { code.ifEmpty { REQUEST } })
        shown = back
        ui = back
        return back
    }

    /** True while the dialog should keep reading the core. */
    val polling: Boolean get() = op.isNotEmpty() && !ui.isFinal

    /** The operation to cancel when the dialog goes away, or null when there is nothing running that this dialog started. */
    fun cancelTarget(): String? = if (op.isNotEmpty() && !ui.isFinal) op else null

    private fun end(last: FxRenewUi): FxRenewUi { ui = last; return last }

    companion object {
        /** The app's own failure words (the core's are in [FxReauthCodes.failures]). */
        const val SUPERSEDED = "superseded" // the core shows a newer renewal
        const val LOST = "lost" // the core shows none: it was restarted, or the operation is gone
        const val REQUEST = "request_failed" // the app could not talk to the core
        const val MAX_POLL_FAILURES = 5

        /** Every failure word the dialog can show: each has a text of its own, `fx_renew_err_<word>`. */
        val allFailureWords: List<String> = FxReauthCodes.failures + listOf(FxReauthCodes.BUSY, SUPERSEDED, LOST, REQUEST)
    }
}
