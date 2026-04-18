from django import forms
from django.contrib.auth import get_user_model
from django.db.models import Q

from intel.access import ADMIN_GROUP, ANALYST_GROUP
from intel.models import Ticket, TicketNote


class _TicketUserChoiceMixin:
    def _configure_user_field(self) -> None:
        field = self.fields.get("assigned_to")
        if not field:
            return
        user_model = get_user_model()
        field.queryset = (
            user_model.objects.filter(is_active=True)
            .filter(Q(groups__name__in=[ANALYST_GROUP, ADMIN_GROUP]) | Q(is_staff=True) | Q(is_superuser=True))
            .distinct()
            .order_by("username")
        )
        field.required = False
        field.empty_label = "Unassigned"


class TicketCreateForm(_TicketUserChoiceMixin, forms.ModelForm):
    class Meta:
        model = Ticket
        fields = ["title", "description", "priority", "assigned_to"]
        widgets = {
            "title": forms.TextInput(attrs={"placeholder": "Investigate suspicious infrastructure cluster"}),
            "description": forms.Textarea(
                attrs={"rows": 4, "placeholder": "Capture initial context, scope, or expected outcome."}
            ),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._configure_user_field()

    def clean_title(self):
        return self.cleaned_data["title"].strip()

    def clean_description(self):
        return self.cleaned_data.get("description", "").strip()


class TicketUpdateForm(_TicketUserChoiceMixin, forms.ModelForm):
    class Meta:
        model = Ticket
        fields = ["title", "description", "status", "priority", "assigned_to"]
        widgets = {
            "description": forms.Textarea(attrs={"rows": 6}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._configure_user_field()

    def clean_title(self):
        return self.cleaned_data["title"].strip()

    def clean_description(self):
        return self.cleaned_data.get("description", "").strip()


class TicketNoteForm(forms.ModelForm):
    class Meta:
        model = TicketNote
        fields = ["body"]
        widgets = {
            "body": forms.Textarea(
                attrs={"rows": 5, "placeholder": "Add investigation notes, pivots, decisions, or follow-up context."}
            ),
        }

    def clean_body(self):
        return self.cleaned_data["body"].strip()
