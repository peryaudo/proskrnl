/*
 * compose.c - the z-order half of the compositor (GUI-4).
 *
 * Wine's server deliberately does not clip top-level siblings out of a
 * window's surface region: "we don't clip out top-level siblings as that's
 * up to the native windowing system" (server/window.c, get_visible_region).
 * Under winex11/winewayland the host compositor owns that occlusion; here
 * winefb IS the native windowing system, so the driver asks the server who
 * is above and clips its flushes accordingly (blit.c).
 *
 * Queried fresh per flush rather than cached: the answer is two small
 * server round-trips over state that any process may change at any moment,
 * and a cache would need exactly the cross-process invalidation protocol
 * this design avoids. Staleness is bounded by one flush: both the clip and
 * the repaint requests (blit.c winefb_window_pos_changed) derive from the
 * same server rectangles, so the picture converges on the next flush of
 * either side.
 */

#include "winefb.h"
#include "wine/debug.h"
#include "wine/server.h"

WINE_DEFAULT_DEBUG_CHANNEL(winefb);

/* Screen rects of the visible top-level windows strictly ABOVE hwnd in the
 * desktop's z-order (the get_window_list reply is topmost first, the same
 * walk the server's own hit-testing does in shallow_window_from_point).
 * Returns how many were filled. If hwnd never appears in the list, nothing
 * is subtracted -- the defensive answer is yesterday's last-writer-wins,
 * not a hole in the picture. */
UINT winefb_windows_above( HWND hwnd, RECT *rects, UINT max_count )
{
    user_handle_t handles[WINEFB_MAX_TOPLEVELS];
    unsigned int count = 0, i;
    UINT above = 0;
    BOOL found = FALSE;
    NTSTATUS status;

    SERVER_START_REQ( get_window_list )
    {
        req->desktop  = 0;
        req->handle   = 0; /* top-level windows of the current desktop */
        req->tid      = 0;
        req->children = 0;
        wine_server_set_reply( req, handles, sizeof(handles) );
        status = wine_server_call( req );
        count = reply->count;
    }
    SERVER_END_REQ;
    if (status || count > WINEFB_MAX_TOPLEVELS) return 0;

    for (i = 0; i < count && !found && above < max_count; i++)
    {
        RECT rect;

        if (handles[i] == wine_server_user_handle( hwnd ))
        {
            found = TRUE;
            break;
        }
        /* Style lives in the session shared mapping, so this is a read,
         * not a round-trip. A window this process cannot resolve answers
         * 0, which reads as invisible -- the safe direction. */
        if (!(NtUserGetWindowLongW( wine_server_ptr_handle( handles[i] ), GWL_STYLE ) & WS_VISIBLE))
            continue;

        SERVER_START_REQ( get_window_rectangles )
        {
            req->handle   = handles[i];
            req->relative = COORDS_SCREEN;
            status = wine_server_call( req );
            rect.left   = reply->window.left;
            rect.top    = reply->window.top;
            rect.right  = reply->window.right;
            rect.bottom = reply->window.bottom;
        }
        SERVER_END_REQ;
        if (status || IsRectEmpty( &rect )) continue;

        rects[above++] = rect;
    }
    return found ? above : 0;
}
