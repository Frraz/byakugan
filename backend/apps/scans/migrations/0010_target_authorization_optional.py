# Deployment privado: a autorização deixa de ser entrada obrigatória do
# usuário. ``authorized_by`` passa a ser auto-preenchido (usuário logado) e
# ``authorization_scope`` cai para o próprio ``value`` quando vazio. O escopo
# fail-closed (RN007) continua valendo — só ganha um default sensato.

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("scans", "0009_alter_exploitationplaybook_category"),
    ]

    operations = [
        migrations.AlterField(
            model_name="target",
            name="authorized_by",
            field=models.CharField(blank=True, default="", max_length=255),
        ),
        migrations.AlterField(
            model_name="target",
            name="authorization_scope",
            field=models.TextField(blank=True, default=""),
        ),
    ]
