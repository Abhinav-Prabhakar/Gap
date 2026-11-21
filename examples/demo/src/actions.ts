import { defineAction, invalidInput, notFound } from "gapmcp-core";
import { z } from "zod";

/**
 * A deliberately small invoicing app. In a real codebase these handlers call
 * application services; the point is that the MCP surface and the HTTP surface
 * share one contract.
 */

interface Customer {
  id: string;
  name: string;
  email: string;
  createdAt: string;
}

interface LineItem {
  sku: string;
  description: string;
  quantity: number;
  unitPrice: number;
}

interface Invoice {
  id: string;
  customerId: string;
  status: "draft" | "sent" | "paid";
  lineItems: LineItem[];
  total: number;
  dueInDays: number;
  createdAt: string;
  sentAt?: string;
}

const customers: Customer[] = [
  { id: "cus_ada", name: "Ada Lovelace", email: "ada@example.com", createdAt: "2025-01-12T10:00:00.000Z" },
  { id: "cus_grace", name: "Grace Hopper", email: "grace@example.com", createdAt: "2025-02-03T09:30:00.000Z" },
  { id: "cus_alan", name: "Alan Turing", email: "alan@example.com", createdAt: "2025-03-21T14:15:00.000Z" },
];

const invoices: Invoice[] = [
  {
    id: "inv_1001",
    customerId: "cus_ada",
    status: "paid",
    lineItems: [{ sku: "ENG-01", description: "Engineering retainer", quantity: 1, unitPrice: 4200 }],
    total: 4200,
    dueInDays: 30,
    createdAt: "2025-04-02T08:00:00.000Z",
    sentAt: "2025-04-02T08:05:00.000Z",
  },
  {
    id: "inv_1002",
    customerId: "cus_grace",
    status: "sent",
    lineItems: [
      { sku: "DES-04", description: "Design sprint", quantity: 2, unitPrice: 1800 },
      { sku: "OPS-02", description: "Ops review", quantity: 1, unitPrice: 600 },
    ],
    total: 4200,
    dueInDays: 14,
    createdAt: "2025-05-11T11:20:00.000Z",
    sentAt: "2025-05-11T11:25:00.000Z",
  },
  {
    id: "inv_1003",
    customerId: "cus_alan",
    status: "draft",
    lineItems: [{ sku: "RES-07", description: "Research package", quantity: 1, unitPrice: 980 }],
    total: 980,
    dueInDays: 30,
    createdAt: "2025-06-01T16:45:00.000Z",
  },
];

const deleted = new Map<string, Invoice>();

const customerSchema = z.object({
  id: z.string().describe("Customer id, e.g. cus_ada."),
  name: z.string().describe("Customer display name."),
  email: z.string().describe("Billing email."),
  createdAt: z.string().describe("ISO-8601 creation timestamp."),
});

const lineItemSchema = z.object({
  sku: z.string().describe("SKU or service code."),
  description: z.string().describe("Line item description."),
  quantity: z.number().int().min(1).describe("Units to bill."),
  unitPrice: z.number().nonnegative().describe("Price per unit in USD."),
});

const invoiceSchema = z.object({
  id: z.string().describe("Invoice id."),
  customerId: z.string().describe("Customer id."),
  status: z.enum(["draft", "sent", "paid"]).describe("Current invoice status."),
  lineItems: z.array(lineItemSchema).describe("Billed line items."),
  total: z.number().describe("Invoice total in USD."),
  dueInDays: z.number().int().describe("Payment terms in days."),
  createdAt: z.string().describe("ISO-8601 creation timestamp."),
  sentAt: z.string().optional().describe("ISO-8601 send timestamp, when sent."),
});

function findInvoice(id: string): Invoice {
  const invoice = invoices.find((item) => item.id === id);
  if (!invoice) throw new Error(`Invoice ${id} not found.`);
  return invoice;
}

export const listCustomers = defineAction({
  name: "customers.list",
  description: "List customers, optionally filtered by a case-insensitive name or email query. Read-only.",
  input: z.object({
    query: z.string().max(200).optional().describe("Substring to match against name or email."),
    limit: z.number().int().min(1).max(100).default(20).describe("Maximum customers to return."),
  }),
  output: z.object({ customers: z.array(customerSchema), total: z.number() }),
  tags: ["read-only"],
  execute: async ({ query, limit }) => {
    const normalized = query?.toLowerCase();
    const matches = normalized
      ? customers.filter(
          (customer) =>
            customer.name.toLowerCase().includes(normalized) ||
            customer.email.toLowerCase().includes(normalized),
        )
      : customers;
    return { customers: matches.slice(0, limit), total: matches.length };
  },
});

export const getCustomer = defineAction({
  name: "customers.get",
  description: "Fetch one customer by id. Returns NOT_FOUND when the customer does not exist. Read-only.",
  input: z.object({ id: z.string().describe("Customer id, e.g. cus_ada.") }),
  output: customerSchema,
  tags: ["read-only"],
  execute: async ({ id }) => {
    const customer = customers.find((item) => item.id === id);
    if (!customer) throw notFound(`Customer ${id} not found.`);
    return customer;
  },
});

export const listInvoices = defineAction({
  name: "invoices.list",
  description: "List invoices with optional status and customer filters. Read-only.",
  input: z.object({
    status: z.enum(["draft", "sent", "paid"]).optional().describe("Filter by invoice status."),
    customerId: z.string().optional().describe("Filter by customer id."),
    limit: z.number().int().min(1).max(100).default(20).describe("Maximum invoices to return."),
  }),
  output: z.object({ invoices: z.array(invoiceSchema), total: z.number() }),
  scopes: ["invoices:read"],
  tags: ["read-only"],
  execute: async ({ status, customerId, limit }) => {
    const matches = invoices.filter(
      (invoice) =>
        (!status || invoice.status === status) &&
        (!customerId || invoice.customerId === customerId),
    );
    return { invoices: matches.slice(0, limit), total: matches.length };
  },
});

export const createInvoice = defineAction({
  name: "invoices.create",
  description:
    "Create a draft invoice for a customer. Computes the total from line items and does not send the invoice. Idempotent when a key is supplied.",
  input: z.object({
    customerId: z.string().describe("Customer id, e.g. cus_grace."),
    lineItems: z
      .array(lineItemSchema)
      .min(1)
      .max(20)
      .describe("Line items to bill. Total = sum(quantity * unitPrice)."),
    dueInDays: z.number().int().min(1).max(90).default(30).describe("Payment terms in days."),
  }),
  output: invoiceSchema,
  scopes: ["invoices:write"],
  risk: "medium",
  idempotent: true,
  ui: {
    route: "/invoices/new",
    action: "invoices.create",
    fields: { customerId: "#customer", total: "#total" },
    submit: "#create-invoice",
    result: "#invoice-id",
  },
  execute: async ({ customerId, lineItems, dueInDays }, ctx) => {
    const customer = customers.find((item) => item.id === customerId);
    if (!customer) throw invalidInput(`Unknown customer ${customerId}.`, { customerId });
    const total = lineItems.reduce((sum, item) => sum + item.quantity * item.unitPrice, 0);
    const invoice: Invoice = {
      id: `inv_${String(1004 + invoices.length).padStart(4, "0")}`,
      customerId,
      status: "draft",
      lineItems,
      total,
      dueInDays,
      createdAt: new Date().toISOString(),
    };
    if (!ctx.dryRun) invoices.push(invoice);
    ctx.logger.info("invoice created", { id: invoice.id, total, dryRun: ctx.dryRun });
    return invoice;
  },
});

export const sendInvoice = defineAction({
  name: "invoices.send",
  description:
    "Email a draft invoice to the customer and mark it sent. This is externally visible and requires human approval.",
  input: z.object({ id: z.string().describe("Invoice id to send, e.g. inv_1003.") }),
  output: invoiceSchema,
  scopes: ["invoices:write"],
  risk: "high",
  confirm: true,
  execute: async ({ id }) => {
    const invoice = findInvoice(id);
    if (invoice.status === "paid") throw new Error("Paid invoices cannot be sent.");
    invoice.status = "sent";
    invoice.sentAt = new Date().toISOString();
    return invoice;
  },
});

export const deleteInvoice = defineAction({
  name: "invoices.delete",
  description:
    "Permanently delete a draft invoice. Fails for sent or paid invoices. Requires confirmation and can be undone for 15 minutes.",
  input: z.object({ id: z.string().describe("Invoice id to delete.") }),
  output: z.object({ id: z.string(), deleted: z.boolean() }),
  scopes: ["invoices:delete"],
  risk: "critical",
  confirm: true,
  idempotent: true,
  async execute({ id }) {
    const invoice = findInvoice(id);
    if (invoice.status !== "draft") throw new Error("Only draft invoices can be deleted.");
    invoices.splice(invoices.indexOf(invoice), 1);
    deleted.set(id, invoice);
    return { id, deleted: true };
  },
  undo: async (_output, input) => {
    const invoice = deleted.get(input.id);
    if (invoice) {
      invoices.push(invoice);
      deleted.delete(input.id);
    }
  },
});

export const revenueReport = defineAction({
  name: "reports.revenue",
  description:
    "Summarize invoice revenue by status for a date range. Read-only and cheap to call repeatedly.",
  input: z.object({
    from: z.string().describe("Inclusive ISO-8601 start date, e.g. 2025-01-01."),
    to: z.string().describe("Inclusive ISO-8601 end date, e.g. 2025-12-31."),
  }),
  output: z.object({
    total: z.number(),
    byStatus: z.record(z.string(), z.number()),
    invoiceCount: z.number(),
  }),
  scopes: ["reports:read"],
  tags: ["read-only"],
  execute: async ({ from, to }) => {
    const start = new Date(from).getTime();
    const end = new Date(to).getTime();
    const matches = invoices.filter((invoice) => {
      const created = new Date(invoice.createdAt).getTime();
      return created >= start && created <= end;
    });
    const byStatus: Record<string, number> = { draft: 0, sent: 0, paid: 0 };
    for (const invoice of matches) byStatus[invoice.status] = (byStatus[invoice.status] ?? 0) + invoice.total;
    return {
      total: matches.reduce((sum, invoice) => sum + invoice.total, 0),
      byStatus,
      invoiceCount: matches.length,
    };
  },
});

export const exportInvoices = defineAction({
  name: "exports.invoices",
  description:
    "Start a background CSV export of invoices. Returns a task id immediately; poll gap.tasks.get for the result.",
  input: z.object({
    status: z.enum(["draft", "sent", "paid"]).optional().describe("Limit the export to one status."),
  }),
  output: z.object({ rows: z.number(), csv: z.string() }),
  scopes: ["invoices:read"],
  risk: "low",
  task: true,
  execute: async ({ status }, ctx) => {
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(resolve, 1200);
      ctx.signal.addEventListener("abort", () => {
        clearTimeout(timer);
        reject(new Error("Export cancelled."));
      });
    });
    const rows = invoices.filter((invoice) => !status || invoice.status === status);
    const csv = [
      "id,customerId,status,total",
      ...rows.map((invoice) => `${invoice.id},${invoice.customerId},${invoice.status},${invoice.total}`),
    ].join("\n");
    return { rows: rows.length, csv };
  },
});

export const actions = [
  listCustomers,
  getCustomer,
  listInvoices,
  createInvoice,
  sendInvoice,
  deleteInvoice,
  revenueReport,
  exportInvoices,
];

export default actions;
