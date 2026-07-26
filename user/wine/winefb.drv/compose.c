/*
 * compose.c - the z-order half of the compositor (GUI-4).
 *
 * Wine's server deliberately does not clip top-level siblings out of a
 * window's surface region: "we don't clip out top-level siblings as that's
 * up to the native windowing system" (server/window.c, get_visible_region).
 * Under winex11/winewayland the host compositor owns that occlusion; here
 * winefb IS the native windowing system, so the driver asks the server who
 * is above and clips its flushes accordingly, and — the other half of the
 * same delegation — repairs what a moved window uncovers (blit.c).
 *
 * Queried fresh per use rather than cached: the answer is two small server
 * round-trips over state that any process may change at any moment, and a
 * cache would need exactly the cross-process invalidation protocol this
 * design avoids. Staleness is bounded by one flush: both the clip and the
 * repaint requests derive from the same server rectangles, so the picture
 * converges on the next flush of either side.
 */

#include "winefb.h"
#include "wine/debug.h"
#include "wine/server.h"

WINE_DEFAULT_DEBUG_CHANNEL(winefb);

/* The desktop's visible top-level windows, topmost first (the get_window_list
 * reply order is the same walk the server's own hit-testing does in
 * shallow_window_from_point), with screen rects. Style is a session
 * shared-mapping read, not a round-trip; a window this process cannot
 * resolve answers 0, which reads as invisible -- the safe direction. */
static UINT query_visible_toplevels( struct winefb_toplevel *out, UINT max_count )
{
    user_handle_t handles[WINEFB_MAX_TOPLEVELS];
    unsigned int count = 0, i;
    UINT found = 0;
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

    for (i = 0; i < count && found < max_count; i++)
    {
        RECT rect;

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

        out[found].hwnd = wine_server_ptr_handle( handles[i] );
        out[found].rect = rect;
        found++;
    }
    return found;
}

/* Screen rects of the visible top-level windows strictly ABOVE hwnd in the
 * desktop's z-order. Returns how many were filled. If hwnd never appears
 * in the list (foreign desktop, destroyed, hidden mid-flush), nothing is
 * subtracted -- the defensive answer is yesterday's last-writer-wins, not
 * a hole in the picture. */
UINT winefb_windows_above( HWND hwnd, RECT *rects, UINT max_count )
{
    struct winefb_toplevel list[WINEFB_MAX_TOPLEVELS];
    UINT count = query_visible_toplevels( list, WINEFB_MAX_TOPLEVELS );
    UINT i, above = 0;

    for (i = 0; i < count; i++)
    {
        if (list[i].hwnd == hwnd) return above;
        if (above < max_count) rects[above++] = list[i].rect;
    }
    return 0; /* hwnd not found */
}

/* Every visible top-level EXCEPT exclude -- the candidates a vacated area
 * may have uncovered (blit.c winefb_window_pos_changed). */
UINT winefb_other_toplevels( HWND exclude, struct winefb_toplevel *out, UINT max_count )
{
    struct winefb_toplevel list[WINEFB_MAX_TOPLEVELS];
    UINT count = query_visible_toplevels( list, WINEFB_MAX_TOPLEVELS );
    UINT i, others = 0;

    for (i = 0; i < count && others < max_count; i++)
    {
        if (list[i].hwnd == exclude) continue;
        out[others++] = list[i];
    }
    return others;
}
