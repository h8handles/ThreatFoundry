class IntelIOC(models.Model):
    # Existing fields...
    
    calculated_score = models.FloatField(null=True, blank=True)
    score_breakdown = models.JSONField(default=dict, blank=True)

    def save(self, *args, **kwargs):
        if not self.calculated_score:
            scorer = ThreatFoundryScorer()
            self.calculated_score = scorer.calculate_score(self.to_dict())
            self.score_breakdown = scorer.get_breakdown()
        super().save(*args, **kwargs)
