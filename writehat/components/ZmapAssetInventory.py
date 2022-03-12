from .base import *

class ZmapAssetInventoryForm(ComponentForm):

    assets_file = forms.FileField(
        label='Assets File',
        widget=forms.FileInput,
        required=True
    )
    field_order = ['name', 'summary', 'pageBreakBefore', 'showTitle']


class Component(BaseComponent):

    default_name = 'Zmap Asset Inventory'
    formClass = ZmapAssetInventoryForm

    # the "templatable" attribute decides whether or not that field
    # gets saved if the report is ever converted into a template
    fieldList = {
        'assets_file': StringField(markdown=True, templatable=True),
    }

    # make sure to specify the HTML template
    htmlTemplate = 'componentTemplates/ZmapAssetInventory.html'

    # Font Awesome icon type + color (HTML/CSS)
    # This is just eye candy in the web app
    iconType = 'fas fa-stream'
    iconColor = 'var(--blue)'

    # the "preprocess" function is executed when the report is rendered
    # use this to perform any last-minute operations on its data
    def preprocess(self, context):
        # TODO Figure out why files can't upload and move the processing logic to the save method.

        context['assets'] = {}


        return context
