# Pylons-to-Flask porting scaffold.


import logging
import os.path
from builtins import KeyError

import flask
from flask_babel import get_locale
from mako.exceptions import text_error_template
from mako.lookup import TemplateLookup
from werkzeug.local import LocalProxy

from linotp.lib.fs_utils import ensure_dir

log = logging.getLogger(__name__)

config = LocalProxy(lambda: flask.current_app.config)

error_document_template = """
    <html>
        <body>
            <p>An error occurred in %(prefix)s</p>
            <p>Error code: %(code)s</p>
            <p>%(message)s</p>
        </body>
    </html>
    """


class RequestContextProxy:
    def __getattr__(self, name):
        try:
            return flask.g.request_context.__getitem__(name)
        except KeyError as exx:
            raise AttributeError(exx) from exx

    def get(self, name, default=None):
        return flask.g.request_context.get(name, default)
        # return flask.g.request_context.__getattribute__(name)

    def __setattr__(self, name, value):
        # flask.g.request_context.__setattr__(name, value)
        flask.g.request_context.__setitem__(name, value)

    def __getitem__(self, key):
        return flask.g.request_context.__getitem__(key)

    def __setitem__(self, key, value):
        flask.g.request_context.__setitem__(key, value)

    def setdefault(self, key, value):
        return flask.g.request_context.setdefault(key, value)

    def items(self):
        return flask.g.request_context.items()

    def __repr__(self, *_args, **_kwargs):
        repr_dict = dict(flask.g.request_context.items())
        return f"{repr_dict!r}"


tmpl_context = RequestContextProxy()


def setup_request_context():
    """
    Set up global request_context
    FIXME: get rid of request_context all together
           or at least initialize it somewhere else
           to get rid of this method
    """
    flask.g.request_context = {}


def setup_mako(app):
    if not hasattr(app, "mako_template_lookup"):
        app.mako_template_lookup = None


def _make_mako_lookup(app):
    # Make a Mako `TemplateLookup` from the app configuration.

    mod_dir = ensure_dir(
        app, "Mako template cache", "CACHE_DIR", "template-cache", mode=0o770
    )

    kwargs = {
        "input_encoding": "utf-8",
        "output_encoding": "utf-8",
        "default_filters": app.config["MAKO_DEFAULT_FILTERS"],
        "imports": [
            ("from flask_babel import gettext as _, ngettext, pgettext, npgettext"),
        ],
        # `module_directory` points to a directory that is used to
        # cache Mako templates that have been compiled to Python code.
        "module_directory": mod_dir,
    }

    # Tokens can come with their own Mako templates, all of which are
    # in the `tokens` folder, but it seems overkill to add an
    # otherwise-empty blueprint for that just so the very contrived
    # blueprint-scanning code can find it. It's easier to add the folder
    # here and omit the blueprint-scanning loop (see below).

    dirs = [
        os.path.join(app.root_path, app.template_folder),
        os.path.join(app.root_path, "tokens"),
    ]
    custom_templates_dir = app.config["CUSTOM_TEMPLATES_DIR"]
    if custom_templates_dir is not None:
        dirs.insert(0, custom_templates_dir)

    # We don't bother with `template_folder` directories of blueprints
    # because we're not using that feature in LinOTP (yet anyway).

    return TemplateLookup(directories=dirs, **kwargs)


class TemplateError(RuntimeError):
    def __init__(self, template):
        self.text = text_error_template().render()
        message = f"Error rendering template '{template.uri}'"
        super().__init__(message)


def render_mako(template_name, extra_context=None):
    """This is loosely compatible with the Pylons `render_mako()`
    function, so we don't need to change all the occurrences of this
    function elsewhere in the code. We try to avoid making *all* global
    variables available to Mako for replacement; in fact most
    templates only refer to the `c` variable, and we pass any additional
    ones in the `extra_context` parameter. Of course we still have
    all the stuff that *Flask* pushes into the template context, and
    eventually the templates may be rewritten to use that.
    """

    app = flask.current_app
    if app.mako_template_lookup is None:
        app.mako_template_lookup = _make_mako_lookup(app)

    if extra_context:
        flask.g.request_context.update(extra_context)

    try:
        template = app.mako_template_lookup.get_template(template_name.lstrip("/"))
        ret = template.render(c=tmpl_context, lang=get_locale().language)
    except TemplateError as e:
        log.error(e.text)
        raise
    return ret
