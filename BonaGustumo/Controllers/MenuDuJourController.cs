using System;
using System.Collections.Generic;
using System.Data;
using System.Data.Entity;
using System.Linq;
using System.Net;
using System.Web;
using System.Web.Mvc;
using BonaGustumo_Library.DAL;
using BonaGustumo_Library.Model;

namespace BonaGustumo.Controllers
{
    [AllowAnonymous]
    public class MenuDuJourController : Controller
    {
        private BonaGustumoContext db = new BonaGustumoContext();

        // GET: MenuDuJour
        public ActionResult Index()
        {
            return View(db.MenuDuJours.ToList());
        }

        // GET: MenuDuJour/Details/5
        public ActionResult Details(int? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            MenuDuJour menuDuJour = db.MenuDuJours.Find(id);
            if (menuDuJour == null)
            {
                return HttpNotFound();
            }
            return View(menuDuJour);
        }

        // GET: MenuDuJour/Create
        public ActionResult Create()
        {
            return View();
        }

        // POST: MenuDuJour/Create
        // Afin de déjouer les attaques par sur-validation, activez les propriétés spécifiques que vous voulez lier. Pour 
        // plus de détails, voir  https://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Create([Bind(Include = "Plat_Id,Plat_Titre,plat_Type,Plat_Commentaire")] MenuDuJour menuDuJour)
        {
            if (ModelState.IsValid)
            {
                db.MenuDuJours.Add(menuDuJour);
                db.SaveChanges();
                return RedirectToAction("Index");
            }

            return View(menuDuJour);
        }

        // GET: MenuDuJour/Edit/5
        public ActionResult Edit(int? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            MenuDuJour menuDuJour = db.MenuDuJours.Find(id);
            if (menuDuJour == null)
            {
                return HttpNotFound();
            }
            return View(menuDuJour);
        }

        // POST: MenuDuJour/Edit/5
        // Afin de déjouer les attaques par sur-validation, activez les propriétés spécifiques que vous voulez lier. Pour 
        // plus de détails, voir  https://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Edit([Bind(Include = "Plat_Id,Plat_Titre,plat_Type,Plat_Commentaire")] MenuDuJour menuDuJour)
        {
            if (ModelState.IsValid)
            {
                db.Entry(menuDuJour).State = EntityState.Modified;
                db.SaveChanges();
                return RedirectToAction("Index");
            }
            return View(menuDuJour);
        }

        // GET: MenuDuJour/Delete/5
        public ActionResult Delete(int? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            MenuDuJour menuDuJour = db.MenuDuJours.Find(id);
            if (menuDuJour == null)
            {
                return HttpNotFound();
            }
            return View(menuDuJour);
        }

        // POST: MenuDuJour/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public ActionResult DeleteConfirmed(int id)
        {
            MenuDuJour menuDuJour = db.MenuDuJours.Find(id);
            db.MenuDuJours.Remove(menuDuJour);
            db.SaveChanges();
            return RedirectToAction("Index");
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                db.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}
