/** @odoo-module */

import { registry } from "@web/core/registry";
import { FormController } from "@web/views/form/form_controller";
import { formView } from "@web/views/form/form_view";
import { patch } from "@web/core/utils/patch";

patch(FormController.prototype, {
    setup() {
        super.setup();
        this.env.bus.on("FIELD_CHANGED", this, ({ name }) => {
            if (name === "payment_type") {
                // Notify the form model to trigger UI visibility updates
                this.model.notify();
            }
        });
    },
});

// Register the view type (optional unless explicitly used in view declaration)
registry.category("views").add("sale_order_form_with_installments", formView);
