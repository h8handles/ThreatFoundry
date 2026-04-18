from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import TestCase
from django.urls import reverse

from intel.access import ANALYST_GROUP, VIEWER_GROUP
from intel.models import Ticket, TicketNote


class TicketingFeatureTests(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.analyst_user = user_model.objects.create_user(username="ticket-analyst", password="test-pass-123")
        self.viewer_user = user_model.objects.create_user(username="ticket-viewer", password="test-pass-123")
        self.analyst_user.groups.add(Group.objects.get(name=ANALYST_GROUP))
        self.viewer_user.groups.add(Group.objects.get(name=VIEWER_GROUP))

    def test_analyst_can_create_view_update_and_note_ticket(self):
        self.client.force_login(self.analyst_user)

        create_response = self.client.post(
            reverse("intel:ticket_list"),
            data={
                "title": "Investigate suspicious cluster",
                "description": "Initial triage context",
                "priority": Ticket.Priority.HIGH,
                "assigned_to": self.analyst_user.pk,
            },
        )

        ticket = Ticket.objects.get(title="Investigate suspicious cluster")
        self.assertRedirects(create_response, reverse("intel:ticket_detail", args=[ticket.pk]))
        self.assertEqual(ticket.created_by, self.analyst_user)
        self.assertEqual(ticket.assigned_to, self.analyst_user)

        detail_response = self.client.get(reverse("intel:ticket_detail", args=[ticket.pk]))
        self.assertContains(detail_response, "Initial triage context")

        update_response = self.client.post(
            reverse("intel:ticket_detail", args=[ticket.pk]),
            data={
                "title": "Investigate suspicious cluster",
                "description": "Updated investigation scope",
                "status": Ticket.Status.IN_PROGRESS,
                "priority": Ticket.Priority.CRITICAL,
                "assigned_to": "",
            },
        )
        self.assertRedirects(update_response, reverse("intel:ticket_detail", args=[ticket.pk]))
        ticket.refresh_from_db()
        self.assertEqual(ticket.status, Ticket.Status.IN_PROGRESS)
        self.assertEqual(ticket.priority, Ticket.Priority.CRITICAL)
        self.assertIsNone(ticket.assigned_to)

        note_response = self.client.post(
            reverse("intel:ticket_note_create", args=[ticket.pk]),
            data={"body": "Pivoted through shared malware family."},
        )
        self.assertRedirects(note_response, reverse("intel:ticket_detail", args=[ticket.pk]))
        note = TicketNote.objects.get(ticket=ticket)
        self.assertEqual(note.author, self.analyst_user)
        self.assertEqual(note.body, "Pivoted through shared malware family.")

    def test_ticket_popout_modes_reuse_authenticated_pages(self):
        self.client.force_login(self.analyst_user)
        ticket = Ticket.objects.create(title="Pop out ticket", created_by=self.analyst_user)

        list_response = self.client.get(f"{reverse('intel:ticket_list')}?popout=1")
        detail_response = self.client.get(f"{reverse('intel:ticket_detail', args=[ticket.pk])}?popout=1")

        self.assertContains(list_response, "ticket-workspace-popout")
        self.assertContains(list_response, "Open Full Tickets")
        self.assertContains(detail_response, "ticket-page-popout")
        self.assertContains(detail_response, "ticket-record-workspace-popout")
        self.assertContains(detail_response, "Open Full Ticket")

    def test_viewer_cannot_access_ticketing_pages(self):
        self.client.force_login(self.viewer_user)
        ticket = Ticket.objects.create(title="Restricted ticket", created_by=self.analyst_user)

        list_response = self.client.get(reverse("intel:ticket_list"))
        detail_response = self.client.get(reverse("intel:ticket_detail", args=[ticket.pk]))
        note_response = self.client.post(reverse("intel:ticket_note_create", args=[ticket.pk]), data={"body": "Nope"})

        self.assertEqual(list_response.status_code, 403)
        self.assertEqual(detail_response.status_code, 403)
        self.assertEqual(note_response.status_code, 403)
