"""Add recipient_id and is_public to Share model

Revision ID: 8b8edba1fa93
Revises: 3d9cd80a8177
Create Date: 2025-03-04 15:10:37.536375

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '8b8edba1fa93'
down_revision = '3d9cd80a8177'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('Share', schema=None) as batch_op:
        batch_op.add_column(sa.Column('recipient_id', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('is_public', sa.Boolean(), nullable=True))
        batch_op.create_foreign_key('fk_share_recipient_id_user', 'User', ['recipient_id'], ['id'])

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('Share', schema=None) as batch_op:
        batch_op.drop_constraint('fk_share_recipient_id_user', type_='foreignkey')
        batch_op.drop_column('is_public')
        batch_op.drop_column('recipient_id')

    # ### end Alembic commands ###
