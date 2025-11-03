
from .QuickDjango import *
from piggySQL import models


# TODO: Finish this interface.
def filter_interface(request):
    table: str = request.GET.get("table", None)
    if table is None:
        return QJR(400, "Table name should be specified, while no table is given.")
    options = transfer(request.GET)
    del options["table"]
    if not table.isdigit():
        return QJR(400, "Table name must be a Integer, string found.")
    table: int = int(table)
    if table > 9:
        return QJR(400, f"Table name must be in range [0, 9], {table} found")
    model: models.models.Model = [models.Article, models.Bug, models.ChatMsg, models.Comment, models.File, models.Message, models.Paper, models.Plan. models.Tag, models.User][table]

