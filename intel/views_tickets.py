from django.db.models import Count
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views.decorators.http import require_POST

from intel.access import ANALYST_GROUP, role_required
from intel.forms import TicketCreateForm, TicketNoteForm, TicketUpdateForm
from intel.models import Ticket


def _is_popout_request(request) -> bool:
    """Return whether the ticket UI should render in standalone popout mode."""
    return request.GET.get("popout") == "1"


def _with_popout(url: str, is_popout: bool) -> str:
    """Preserve the layout-only popout flag across ticket redirects."""
    return f"{url}?popout=1" if is_popout else url


def _ticket_detail_context(request, ticket, *, update_form=None, note_form=None):
    """Build shared context for ticket detail rendering and validation errors.

    Both update and note submissions return to the same ticket workspace. This
    helper keeps the selected ticket, forms, chronological notes, and popout URL
    consistent for normal GETs, failed update POSTs, and failed note POSTs.
    """
    is_popout = _is_popout_request(request)
    return {
        "ticket": ticket,
        "update_form": update_form or TicketUpdateForm(instance=ticket),
        "note_form": note_form or TicketNoteForm(),
        "notes": ticket.notes.select_related("author").all(),
        "is_popout": is_popout,
        "popout_url": _with_popout(reverse("intel:ticket_detail", args=[ticket.pk]), True),
    }


@role_required(ANALYST_GROUP)
def ticket_list_view(request):
    """Render the analyst ticket queue and handle new ticket creation."""
    is_popout = _is_popout_request(request)
    selected_status = str(request.GET.get("status") or "").strip()
    valid_statuses = {value for value, _label in Ticket.Status.choices}
    if selected_status not in valid_statuses:
        selected_status = ""

    tickets = (
        Ticket.objects.select_related("created_by", "assigned_to")
        .annotate(note_count=Count("notes"))
        .order_by("-updated_at", "-created_at")
    )
    if selected_status:
        tickets = tickets.filter(status=selected_status)

    create_form = TicketCreateForm()
    if request.method == "POST":
        create_form = TicketCreateForm(request.POST)
        if create_form.is_valid():
            ticket = create_form.save(commit=False)
            ticket.created_by = request.user
            ticket.save()
            return redirect(_with_popout(reverse("intel:ticket_detail", args=[ticket.pk]), is_popout))

    context = {
        "tickets": tickets,
        "create_form": create_form,
        "status_choices": Ticket.Status.choices,
        "selected_status": selected_status,
        "is_popout": is_popout,
        "popout_url": _with_popout(reverse("intel:ticket_list"), True),
    }
    status_code = 400 if request.method == "POST" and create_form.errors else 200
    return render(request, "intel/ticket_list.html", context, status=status_code)


@role_required(ANALYST_GROUP)
def ticket_detail_view(request, pk: int):
    """Render and update a ticket record without changing note history."""
    ticket = get_object_or_404(Ticket.objects.select_related("created_by", "assigned_to"), pk=pk)
    if request.method == "POST":
        update_form = TicketUpdateForm(request.POST, instance=ticket)
        if update_form.is_valid():
            update_form.save()
            return redirect(_with_popout(reverse("intel:ticket_detail", args=[ticket.pk]), _is_popout_request(request)))
        return render(
            request,
            "intel/ticket_detail.html",
            _ticket_detail_context(request, ticket, update_form=update_form),
            status=400,
        )

    return render(request, "intel/ticket_detail.html", _ticket_detail_context(request, ticket))


@require_POST
@role_required(ANALYST_GROUP)
def ticket_note_create_view(request, pk: int):
    """Append a note to a ticket while preserving auth, CSRF, and popout state."""
    ticket = get_object_or_404(Ticket.objects.select_related("created_by", "assigned_to"), pk=pk)
    note_form = TicketNoteForm(request.POST)
    if note_form.is_valid():
        note = note_form.save(commit=False)
        note.ticket = ticket
        note.author = request.user
        note.save()
        return redirect(_with_popout(reverse("intel:ticket_detail", args=[ticket.pk]), _is_popout_request(request)))

    return render(
        request,
        "intel/ticket_detail.html",
        _ticket_detail_context(request, ticket, note_form=note_form),
        status=400,
    )
